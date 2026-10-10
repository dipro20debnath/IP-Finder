# Test certificate

`cert.pem` / `key.pem` are a throwaway, self-signed test pair made for IP Finder's
tests only (it protects nothing):

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout key.pem -out cert.pem -days 36500 \
      -subj "/CN=example.test/O=IP Finder Test" \
      -addext "subjectAltName=DNS:example.test,DNS:www.example.test,IP:192.0.2.10,IP:2001:db8::10"

The 100-year lifetime makes the notAfter date use GeneralizedTime, which the
X.509 reader must handle.
