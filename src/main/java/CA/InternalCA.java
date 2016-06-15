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
package CA;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Created by evilisn(kasimok@163.com)) on 2016/6/5.
 */
@Configuration
public class InternalCA {
    private static Logger LOG = LoggerFactory.getLogger(InternalCA.class);

    public InternalCA() {
        // initialize BouncyCastle
        Security.addProvider(new BouncyCastleProvider());
        LOG.info("Initialized BouncyCastle...");
    }

    /**
     * Method to read private key from file.
     *
     * @param inputStream
     *
     * @return
     */
    private PrivateKey readPrivateKey(InputStream inputStream) {
        try {
            PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(IOUtils.toByteArray(inputStream));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privKey = kf.generatePrivate(kspec);
            return privKey;
        } catch (Exception e) {
            LOG.info("Cannot load private key: " + e.getMessage());
            return null;
        }
    }

    /**
     * Method to read cert from file.
     *
     * @param inputStream
     *
     * @return
     */
    private X509CertificateHolder readCert(InputStream inputStream) {
        X509CertificateHolder x509CertificateHolder;
        try {
            x509CertificateHolder = new X509CertificateHolder(IOUtils.toByteArray(inputStream));
        } catch (Exception e) {
            LOG.info("Cannot parse Internal CA certificate: " + e.getMessage());
            return null;
        }
        return x509CertificateHolder;
    }

    @Bean
    public X509CertificateHolder x509CertificateHolder() throws IOException {
        //Get file from resources folder
        Resource resource = new ClassPathResource("certs/root/ca.cer.der");
        return readCert(resource.getInputStream());
    }

    @Bean
    public PrivateKey privateKey() throws IOException {
        //Get file from resources folder
        Resource resource = new ClassPathResource("certs/root/ca-key.pkcs8");
        return readPrivateKey(resource.getInputStream());
    }
}
