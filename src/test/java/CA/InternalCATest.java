package CA;

import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.core.IsNull.notNullValue;

/**
 * Created by evilisn(kasimok@163.com)) on 2016/6/5.
 */
public class InternalCATest {
    InternalCA internalCA;

    @Before
    public void setUp() throws Exception {
        internalCA = new InternalCA();
    }

    @Test
    public void readCert() throws Exception {
        MatcherAssert.assertThat(internalCA.x509CertificateHolder(), notNullValue());
    }

    @Test
    public void readPrivateKey() throws Exception {
        MatcherAssert.assertThat(internalCA.privateKey(),notNullValue());
    }

}