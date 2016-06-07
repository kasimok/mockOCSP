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
package IntergrationTest;

import Controllers.OCSPController;
import Main.MainApplication;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import sun.security.provider.certpath.OCSP;
import sun.security.x509.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * Created by evilisn(kasimok@163.com)) on 2016/6/6.
 */

@RunWith (SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration (MainApplication.class)
@WebIntegrationTest
//This will boot the Spring Web server for integration testing. For full test of the web application....
public class OCSPIntegrationTest {
    private static Logger LOG = LoggerFactory.getLogger(OCSPController.class);

    @Value ("${server.port}")
    private int serverPort;

    private URI OCSP_URL;

    private static final int MIN_PORT_NUMBER = 0;
    private static final int MAX_PORT_NUMBER = 65535;
    private X509Certificate clientCert;
    private X509Certificate issuerCert;


    @Before
    public void setUp() throws Exception {
        OCSP_URL = new URI("http://localhost:" + serverPort + "/verify");
        RandomAccessFile raf = new RandomAccessFile("certs/client/client.cer.pem", "r");
        byte[] buf = new byte[(int) raf.length()];
        raf.readFully(buf);
        raf.close();
        clientCert = readPemCert(buf);
        MatcherAssert.assertThat(clientCert, CoreMatchers.notNullValue());
        issuerCert = getX509Certificate(httpGetBin(getIssuerCertURL(clientCert), true));
        MatcherAssert.assertThat(issuerCert, CoreMatchers.notNullValue());
    }

    @Test
    public void testServerPortListening() throws Exception {
        MatcherAssert.assertThat(available(serverPort), CoreMatchers.equalTo(false));
    }


    @Test
    public void testUnknown() throws Exception {
        OCSP.RevocationStatus.CertStatus resp = OCSP.check(clientCert, issuerCert, OCSP_URL, null, null).getCertStatus();
        System.out.println(resp);
    }



    /**
     * Method to test a port is available.
     *
     * @param port
     *
     * @return
     */
    private boolean available(int port) {
        if (port < MIN_PORT_NUMBER || port > MAX_PORT_NUMBER) {
            throw new IllegalArgumentException("Invalid start port: " + port);
        }
        ServerSocket ss = null;
        DatagramSocket ds = null;
        try {
            ss = new ServerSocket(port);
            ss.setReuseAddress(true);
            ds = new DatagramSocket(port);
            ds.setReuseAddress(true);
            return true;
        } catch (IOException e) {
        } finally {
            if (ds != null) {
                ds.close();
            }
            if (ss != null) {
                try {
                    ss.close();
                } catch (IOException e) {
                /* should not be thrown */
                }
            }
        }
        return false;
    }

    /**
     * Read PEM certificate into javax.security.x509Certificate.
     *
     * @param pemCert
     *
     * @return
     */
    private X509Certificate readPemCert(byte[] pemCert) {
        CertificateFactory certificateFactory = null;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        X509Certificate x509cert;
        InputStream stream = new ByteArrayInputStream(pemCert);
        try {
            x509cert = (X509Certificate) certificateFactory.generateCertificate(stream);
            return x509cert;
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] httpGetBin(URI uri, boolean bActiveCheckUnknownHost) throws Exception {
        InputStream is = null;
        InputStream is_temp = null;
        try {
            if (uri == null) return null;
            URL url = uri.toURL();
            if (bActiveCheckUnknownHost) {
                url.getProtocol();
                String host = url.getHost();
                int port = url.getPort();
                if (port == -1)
                    port = url.getDefaultPort();
                InetSocketAddress isa = new InetSocketAddress(host, port);
                if (isa.isUnresolved()) {
                    //fix JNLP popup error issue
                    throw new UnknownHostException("Host Unknown:" + isa.toString());

                }

            }
            HttpURLConnection uc = (HttpURLConnection) url.openConnection();
            uc.setDoInput(true);
            uc.setAllowUserInteraction(false);
            uc.setInstanceFollowRedirects(true);
            setTimeout(uc);
            String contentEncoding = uc.getContentEncoding();
            int len = uc.getContentLength();
            // is = uc.getInputStream();
            if (contentEncoding != null && contentEncoding.toLowerCase().indexOf("gzip") != -1) {
                is_temp = uc.getInputStream();
                is = new GZIPInputStream(is_temp);

            } else if (contentEncoding != null && contentEncoding.toLowerCase().indexOf("deflate") != -1) {
                is_temp = uc.getInputStream();
                is = new InflaterInputStream(is_temp);

            } else {
                is = uc.getInputStream();

            }
            if (len != -1) {
                int ch, i = 0;
                byte[] res = new byte[len];
                while ((ch = is.read()) != -1) {
                    res[i++] = (byte) (ch & 0xff);

                }
                return res;

            } else {
                ArrayList<byte[]> buffer = new ArrayList<>();
                int buf_len = 1024;
                byte[] res = new byte[buf_len];
                int ch, i = 0;
                while ((ch = is.read()) != -1) {
                    res[i++] = (byte) (ch & 0xff);
                    if (i == buf_len) {
                        //rotate
                        buffer.add(res);
                        i = 0;
                        res = new byte[buf_len];

                    }

                }
                int total_len = buffer.size() * buf_len + i;
                byte[] buf = new byte[total_len];
                for (int j = 0 ; j < buffer.size() ; j++) {
                    System.arraycopy(buffer.get(j), 0, buf, j * buf_len, buf_len);

                }
                if (i > 0) {
                    System.arraycopy(res, 0, buf, buffer.size() * buf_len, i);

                }
                return buf;

            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;

        } finally {
            closeInputStream(is_temp);
            closeInputStream(is);

        }

    }

    private void closeInputStream(InputStream is) {
        try {
            if (is != null)
                is.close();

        } catch (IOException e) {
            e.printStackTrace();

        }

    }

    private void setTimeout(URLConnection conn) {
        conn.setConnectTimeout(10 * 1000);
        conn.setReadTimeout(10 * 1000);

    }

    private X509Certificate getX509Certificate(byte[] bcert) throws CertificateException, IOException {
        if (bcert == null)
            return null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream bais = new ByteArrayInputStream(bcert);
        X509Certificate x509cert = (X509Certificate) cf
                .generateCertificate(bais);
        bais.close();
        return x509cert;
    }

    private URI getIssuerCertURL(X509Certificate var0) {
        try {
            return getIssuerCertURL(X509CertImpl.toImpl(var0));
        } catch (CertificateException var2) {
            return null;
        }
    }

    /**
     * Extract the issuer cert's URI from cert.
     *
     * @param var0
     *
     * @return
     */
    private URI getIssuerCertURL(X509CertImpl var0) {
        AuthorityInfoAccessExtension var1 = var0.getAuthorityInfoAccessExtension();
        if (var1 == null) {
            LOG.error("No AIA info found in cert.");
            return null;
        } else {
            List var2 = var1.getAccessDescriptions();
            Iterator var3 = var2.iterator();
            while (var3.hasNext()) {
                AccessDescription var4 = (AccessDescription) var3.next();
                if (var4.getAccessMethod().equals(AccessDescription.Ad_CAISSUERS_Id)) {
                    GeneralName var5 = var4.getAccessLocation();
                    if (var5.getType() == 6) {
                        URIName var6 = (URIName) var5.getName();
                        return var6.getURI();
                    }
                }
            }
            return null;
        }
    }
}
