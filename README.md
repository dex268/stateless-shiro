# stateless-shiro
spring boot + shiro (stateless)

----------------------------

gen private/public key

----------------------------

     public static void main (String[] args) throws Exception {
        Map<String, String> map = RsaUtil.generateKeyPair();
        
        String publicKeyStr = map.get("publicKey");
        String privateKeyStr = map.get("privateKey");

        System.out.println("publicKey:" + publicKeyStr);
        System.out.println("privateKey:" + privateKeyStr);

        Key privateKey = RsaUtil.getPrivateKey(privateKeyStr);

        PemObject rsaPrivateKey = new PemObject("RSA PRIVATE KEY", privateKey.getEncoded());
        StringWriter rsaPrivateKeyWriter = new StringWriter();
        PemWriter privateKeyPemWriter = new PemWriter(rsaPrivateKeyWriter);
        privateKeyPemWriter.writeObject(rsaPrivateKey);
        privateKeyPemWriter.close();
        System.out.println(rsaPrivateKeyWriter.toString());

        Key publicKey = RsaUtil.getPublicKey(publicKeyStr);

        byte[] pubBytes = publicKey.getEncoded();
        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(pubBytes);
        ASN1Primitive primitive = spkInfo.parsePublicKey();
        PemObject rsaPublicKey = new PemObject("RSA PUBLIC KEY", primitive.getEncoded());
        StringWriter rsaPublicKeyWriter = new StringWriter();
        PemWriter publicKeyPemWriter = new PemWriter(rsaPublicKeyWriter);
        publicKeyPemWriter.writeObject(rsaPublicKey);
        publicKeyPemWriter.close();
        System.out.println(rsaPublicKeyWriter.toString());


        System.out.println("privateKey:"+privateKey.getAlgorithm()+","+privateKey.getFormat()+",");
        System.out.println("publicKey:"+publicKey.getAlgorithm()+","+publicKey.getFormat()+",");
        String content = "abc";

        String cipher = RsaUtil.encrypt(privateKeyStr, content);
        System.out.println("cipher:" + cipher);

        String plaintext = RsaUtil.decrypt(publicKeyStr, cipher);
        System.out.println("plaintext:" + plaintext);


        System.out.println("[demo]get pub key by private key:");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(RsaUtil.getPrivateKey(privateKeyStr).getEncoded());
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PrivateKey demoPrivateKey = kf.generatePrivate(keySpec);
        RSAPrivateCrtKey privk = (RSAPrivateCrtKey) demoPrivateKey;

        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey demoPublicKey = keyFactory.generatePublic(publicKeySpec);
        System.out.println("pub key:" + new String(Base64.getEncoder().encode(demoPublicKey.getEncoded())));

    }
