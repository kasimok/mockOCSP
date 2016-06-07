/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package Controllers;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.GregorianCalendar;
import sun.security.provider.certpath.OCSP;

/**
 * Created by evilisn(kasimok@163.com)) on 2016/6/6.
 */
@Controller
@ComponentScan ({"CA"})
public class OCSPController {

    private static Logger LOG = LoggerFactory.getLogger(OCSPController.class);


    /**
     * OCSP Signer's cert.
     */
    private X509CertificateHolder x509CertificateHolder;

    /**
     * OCSP Signer's private keys.
     */

    private PrivateKey privateKey;


    private boolean bRequireRequestSignature = true;
    private boolean bRequireNonce = true;

    @Autowired
    public void setX509CertificateHolder(X509CertificateHolder x509CertificateHolder) {
        this.x509CertificateHolder = x509CertificateHolder;
    }

    @Autowired
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Method to deal with a ocsp query request. The OCSP request method can be GET or POST.
     *
     * @return
     */
    @RequestMapping (value = "/verify", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/ocsp-response")
    @ResponseBody
    public byte[] doOCSP(HttpServletRequest httpServletRequest) throws IOException {
        InputStream inputStream = httpServletRequest.getInputStream();
        byte[] requestBytes = new byte[10000];
        int requestSize = inputStream.read(requestBytes);
        LOG.info("Received OCSP request, size: " + requestSize);
        byte[] responseBytes = processOcspRequest(requestBytes);
        return responseBytes;
    }

    private byte[] processOcspRequest(byte[] requestBytes) {
        try {
            // get request info
            OCSPReq ocspRequest = new OCSPReq(requestBytes);
            X509CertificateHolder[] requestCerts = ocspRequest.getCerts();
            Req[] requestList = ocspRequest.getRequestList();
            // setup response
            BasicOCSPRespBuilder responseBuilder = new BasicOCSPRespBuilder(new RespID(x509CertificateHolder.getSubject()));
            LOG.info("OCSP request version: " + ocspRequest.getVersionNumber() + ", Requestor name: " + ocspRequest.getRequestorName()
                    + ", is signed: " + ocspRequest.isSigned() + ", has extentions: " + ocspRequest.hasExtensions()
                    + ", number of additional certificates: " + requestCerts.length + ", number of certificate ids to verify: " + requestList.length);
            int ocspResult = OCSPRespBuilder.SUCCESSFUL;
            // check request signature
            if (ocspRequest.isSigned()) {
                LOG.info("OCSP Request verify request signature: try certificates from request");
                boolean bRequestSignatureValid = false;
                for (X509CertificateHolder cert : ocspRequest.getCerts()) {
                    ContentVerifierProvider cpv = new JcaContentVerifierProviderBuilder().setProvider("BC").build(cert);
                    bRequestSignatureValid = ocspRequest.isSignatureValid(cpv);
                    if (bRequestSignatureValid) {
                        break;
                    }
                }
                if (!bRequestSignatureValid) {
                    LOG.info("OCSP Request verify request signature: try CA certificate");
                    ContentVerifierProvider cpv = new JcaContentVerifierProviderBuilder().setProvider("BC").build(x509CertificateHolder);
                    bRequestSignatureValid = ocspRequest.isSignatureValid(cpv);
                }
                if (bRequestSignatureValid) {
                    LOG.info("OCSP Request signature validation successful");
                } else {
                    LOG.info("OCSP Request signature validation failed");
                    ocspResult = OCSPRespBuilder.UNAUTHORIZED;
                }
            } else {
                if (bRequireRequestSignature) {
                    LOG.info("OCSP Request signature is not present but required, fail the request");
                    ocspResult = OCSPRespBuilder.SIG_REQUIRED;
                }
            }
            // process nonce
            Extension extNonce = ocspRequest.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"));
            if (extNonce != null) {
                LOG.info("Nonce is present in the request");
                responseBuilder.setResponseExtensions(new Extensions(extNonce));
            } else {
                LOG.info("Nonce is not present in the request");
                if (bRequireNonce) {
                    LOG.info("Nonce is required, fail the request");
                    ocspResult = OCSPRespBuilder.UNAUTHORIZED;
                }
            }
            // check all certificate serial numbers
            if (ocspResult == OCSPRespBuilder.SUCCESSFUL) {
                for (Req req : requestList) {
                    CertificateID certId = req.getCertID();
                    String serialNumber = "0x" + certId.getSerialNumber().toString(16);
                    CertificateStatus certificateStatus = null;
                    // check certId issuer/public key hash
                    LOG.info("Check issuer for certificate entry serial number: " + serialNumber);
                    if (certId.matchesIssuer(x509CertificateHolder, new BcDigestCalculatorProvider())) {
                        LOG.info("Check issuer successful");
                    } else {
                        LOG.info("Check issuer failed. Status unknown");
                        certificateStatus = new UnknownStatus();
                    }
                    if (certificateStatus == null) {
                        LOG.info("Check revocation status for certificate entry serial number: " + serialNumber);
                        if (serialNumber.equals("0x100001")) {
                            certificateStatus = CertificateStatus.GOOD;
                            LOG.info("Status good");
                        } else if (serialNumber.equals("0x100002")) {
                            LOG.info("Status revoked");
                            Calendar cal = new GregorianCalendar();
                            cal.set(2013, 12, 1);
                            certificateStatus = new RevokedStatus(cal.getTime(), 16);
                        } else {
                            LOG.info("Status unknown");
                            certificateStatus = new UnknownStatus();
                        }
                    }
                    Calendar thisUpdate = new GregorianCalendar();
                    thisUpdate.set(2013, 12, 1);
                    Calendar nextUpdate = new GregorianCalendar();
                    nextUpdate.set(2014, 2, 1);
                    responseBuilder.addResponse(certId, certificateStatus, thisUpdate.getTime(), nextUpdate.getTime(), null);
                }
            }
            X509CertificateHolder[] chain = {x509CertificateHolder};
            ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privateKey);
            BasicOCSPResp ocspResponse = responseBuilder.build(signer, chain, Calendar.getInstance().getTime());
            OCSPRespBuilder ocspResponseBuilder = new OCSPRespBuilder();
            byte[] encoded = ocspResponseBuilder.build(ocspResult, ocspResponse).getEncoded();
            LOG.info("Sending OCSP response to client, size: " + encoded.length);
            return encoded;

        } catch (Exception e) {
            LOG.error("Exception during processing OCSP request: " + e.getMessage());
        }
        return null;
    }

}
