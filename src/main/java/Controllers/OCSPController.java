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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;


/**
 * Created by evilisn(kasimok@163.com)) on 2016/6/6.
 */
@Controller
@ComponentScan ({"CA"})
public class OCSPController {

    private static Logger LOG = LoggerFactory.getLogger(OCSPController.class);

    private boolean bRequireNonce = true;


    private enum OCSP_PROCESS_MODE {
        AUTO(0, "AUTO"),
        GOOD(1, "GOOD"),
        REVOKED(2, "REVOKED"),
        UNKNOWN(3, "UNKNOWN");

        private final int MODE;
        private final String DISP;

        OCSP_PROCESS_MODE(int mode, String disp) {
            this.MODE = mode;
            DISP = disp;
        }

        public static OCSP_PROCESS_MODE getOCSP_PROCESS_MODE(int ocsp_process_mode) {
            for (OCSP_PROCESS_MODE mode : OCSP_PROCESS_MODE.values()) {
                if (mode.MODE == ocsp_process_mode) return mode;
            }
            throw new IllegalArgumentException("Mode not supported.");
        }

        @Override
        public String toString() {
            return "OCSP_PROCESS_MODE{" +
                    "MODE=" + MODE +
                    ", DISP='" + DISP + '\'' +
                    '}';
        }
    }


    public static void setOcsp_process_mode(OCSP_PROCESS_MODE iocsp_process_mode) {
        ocsp_process_mode = iocsp_process_mode;
    }

    private static OCSP_PROCESS_MODE ocsp_process_mode = OCSP_PROCESS_MODE.GOOD;

    /**
     * OCSP Signer's cert.
     */
    private static X509CertificateHolder x509CertificateHolder;

    /**
     * OCSP Signer's private keys.
     */

    private static PrivateKey privateKey;


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
     * @return a valid OCSP response.
     */
    @RequestMapping (value = "/verify-mocked-auto", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/ocsp-response")
    @ResponseBody
    public byte[] doOCSPAuto(HttpServletRequest httpServletRequest) throws IOException {
        InputStream inputStream = httpServletRequest.getInputStream();
        byte[] requestBytes = new byte[10000];
        int requestSize = inputStream.read(requestBytes);
        LOG.info("Received OCSP request, size: " + requestSize);
        byte[] responseBytes = processOcspRequest(requestBytes, OCSP_PROCESS_MODE.AUTO);
        return responseBytes;
    }


    /**
     * Mocked method to deal with a ocsp query request. The OCSP request method can be GET or POST.
     *
     * @return a valid OCSP response to tell the client OCSP is <b>Good</b>!
     */
    @RequestMapping (value = "/verify-mocked-good", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/ocsp-response")
    @ResponseBody
    public byte[] doOCSPGood(HttpServletRequest httpServletRequest) throws IOException {
        InputStream inputStream = httpServletRequest.getInputStream();
        byte[] requestBytes = new byte[10000];
        int requestSize = inputStream.read(requestBytes);
        LOG.info("Received OCSP request, size: " + requestSize);
        byte[] responseBytes = processOcspRequest(requestBytes, OCSP_PROCESS_MODE.GOOD);
        return responseBytes;
    }

    /**
     * Mocked method to deal with a ocsp query request. The OCSP request method can be GET or POST.
     *
     * @return a valid OCSP response to tell the client OCSP is <b>Revoked</b>!
     */
    @RequestMapping (value = "/verify-mocked-revoked", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/ocsp-response")
    @ResponseBody
    public byte[] doOCSPRevoked(HttpServletRequest httpServletRequest) throws IOException {
        InputStream inputStream = httpServletRequest.getInputStream();
        byte[] requestBytes = new byte[10000];
        int requestSize = inputStream.read(requestBytes);
        LOG.info("Received OCSP request, size: " + requestSize);
        byte[] responseBytes = processOcspRequest(requestBytes, OCSP_PROCESS_MODE.REVOKED);
        return responseBytes;
    }


    /**
     * Mocked method to deal with a ocsp query request. The OCSP request method can be GET or POST.
     *
     * @return a valid OCSP response to tell the client OCSP is <b>Unknown</b>!
     */
    @RequestMapping (value = "/verify-mocked-unknown", method = {RequestMethod.POST, RequestMethod.GET}, produces = "application/ocsp-response")
    @ResponseBody
    public byte[] doOCSPUnknown(HttpServletRequest httpServletRequest) throws IOException {
        InputStream inputStream = httpServletRequest.getInputStream();
        byte[] requestBytes = new byte[10000];
        int requestSize = inputStream.read(requestBytes);
        LOG.info("Received OCSP request, size: " + requestSize);
        byte[] responseBytes = processOcspRequest(requestBytes, OCSP_PROCESS_MODE.UNKNOWN);
        return responseBytes;
    }

    /**
     * Manually set the OCSP response mode for testing purpose.
     *
     * @return
     */
    @RequestMapping (value = "/set-response-mode", method = {RequestMethod.GET})
    @ResponseBody
    public String doSetMode(@RequestParam (value = "mode", defaultValue = "0") String mode) {
        try {
            final int iOcspMode = Integer.valueOf(mode);
            OCSP_PROCESS_MODE MODE = OCSP_PROCESS_MODE.getOCSP_PROCESS_MODE(iOcspMode);
            setOcsp_process_mode(MODE);
            String string = String.format("Server mode has been changed to [%s].", MODE);
            LOG.warn(string);
            return string;
        } catch (IllegalArgumentException e) {
            LOG.error(String.format("Illegal mode:[%s]", mode));
            return "Illegal mode.";
        }
    }

    /**
     * Forwarding request to certain according to current set mode.
     *
     * @return
     */
    @RequestMapping ({"/"})
    public String execute() {
        LOG.info(String.format("System ocsp mode:[%s]", ocsp_process_mode));
        switch (ocsp_process_mode) {
            case GOOD:
                return "forward:/verify-mocked-good";
            case REVOKED:
                return "forward:/verify-mocked-revoked";
            case UNKNOWN:
                return "forward:/verify-mocked-unknown";
            case AUTO:
                return "forward:/verify-mocked-auto";
            default:
                return "forward:/verify-mocked-good";
        }
    }


    /**
     * Method to do OCSP response to client.
     *
     * @param requestBytes
     * @param mode
     *
     * @return
     *
     * @throws NotImplementedException
     */
    private byte[] processOcspRequest(byte[] requestBytes, OCSP_PROCESS_MODE mode) throws NotImplementedException {
        try {
            // get request info
            OCSPReq ocspRequest = new OCSPReq(requestBytes);
            X509CertificateHolder[] requestCerts = ocspRequest.getCerts();
            Req[] requestList = ocspRequest.getRequestList();
            // setup response
            BasicOCSPRespBuilder responseBuilder = new BasicOCSPRespBuilder(new RespID(x509CertificateHolder.getSubject()));
            LOG.info("OCSP request version: " + ocspRequest.getVersionNumber() + ", Requester name: " + ocspRequest.getRequestorName()
                    + ", is signed: " + ocspRequest.isSigned() + ", has extensions: " + ocspRequest.hasExtensions()
                    + ", number of additional certificates: " + requestCerts.length + ", number of certificate ids to verify: " + requestList.length);
            int ocspResult = OCSPRespBuilder.SUCCESSFUL;
            switch (mode) {
                case AUTO:
                    LOG.error("Auto OCSP server is not implemented in this version.");
                    throw new NotImplementedException();
                case GOOD:
                    LOG.warn("Mocked mode, server will always return Good ocsp response");
                    for (Req req : requestList) {
                        CertificateID certId = req.getCertID();
                        String serialNumber = "0x" + certId.getSerialNumber().toString(16);
                        LOG.debug(String.format("Processing request for cert serial number:[%s]", serialNumber));
                        CertificateStatus certificateStatus = CertificateStatus.GOOD;
                        Calendar thisUpdate = new GregorianCalendar();
                        Date now = thisUpdate.getTime();
                        thisUpdate.add(Calendar.DAY_OF_MONTH, 7);
                        Date nexUpdate = thisUpdate.getTime();
                        responseBuilder.addResponse(certId, certificateStatus, now, nexUpdate, null);
                    }
                    break;
                case REVOKED:
                    LOG.warn("Mocked mode, server will always return REVOKED ocsp response");
                    for (Req req : requestList) {
                        CertificateID certId = req.getCertID();
                        String serialNumber = "0x" + certId.getSerialNumber().toString(16);
                        LOG.debug(String.format("Processing request for cert serial number:[%s]", serialNumber));
                        Calendar cal = new GregorianCalendar();
                        cal.add(Calendar.DAY_OF_MONTH, -7);//Set revoked 7 days ago.
                        CertificateStatus certificateStatus = new RevokedStatus(cal.getTime(), 16);
                        Calendar thisUpdate = new GregorianCalendar();
                        Date now = thisUpdate.getTime();
                        thisUpdate.add(Calendar.DAY_OF_MONTH, 7);
                        Date nexUpdate = thisUpdate.getTime();
                        responseBuilder.addResponse(certId, certificateStatus, now, nexUpdate, null);
                    }
                    break;
                case UNKNOWN:
                    LOG.warn("Mocked mode, server will always return Known ocsp response");
                    for (Req req : requestList) {
                        CertificateID certId = req.getCertID();
                        String serialNumber = "0x" + certId.getSerialNumber().toString(16);
                        LOG.debug(String.format("Processing request for cert serial number:[%s]", serialNumber));
                        CertificateStatus certificateStatus = new UnknownStatus();
                        Calendar thisUpdate = new GregorianCalendar();
                        Date now = thisUpdate.getTime();
                        thisUpdate.add(Calendar.DAY_OF_MONTH, 7);
                        Date nexUpdate = thisUpdate.getTime();
                        responseBuilder.addResponse(certId, certificateStatus, now, nexUpdate, null);
                    }
                    break;
            }
            // process nonce
            Extension extNonce = ocspRequest.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"));
            if (extNonce != null) {
                LOG.debug("Nonce is present in the request");
                responseBuilder.setResponseExtensions(new Extensions(extNonce));
            } else {
                LOG.info("Nonce is not present in the request");
                if (bRequireNonce) {
                    LOG.info("Nonce is required, fail the request");
                    ocspResult = OCSPRespBuilder.UNAUTHORIZED;
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
            e.printStackTrace();
        }
        return null;
    }

}
