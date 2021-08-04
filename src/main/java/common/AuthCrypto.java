package common;

import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public final class AuthCrypto {
   public Cipher cipher;
   public Key pubkey = null;
   protected String error = null;

   public AuthCrypto() {
      try {
         this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
         this.load();
      } catch (Exception var2) {
         this.error = "Could not initialize crypto";
         MudgeSanity.logException("AuthCrypto init", var2, false);
      }

   }

   public void load() {
      try {
         byte[] var1 = CommonUtils.readAll(CommonUtils.class.getClassLoader().getResourceAsStream("resources/authkey.pub"));
         byte[] var2 = CommonUtils.MD5(var1);
         if (!"8bb4df00c120881a1945a43e2bb2379e".equals(CommonUtils.toHex(var2))) {
            CommonUtils.print_error("Invalid authorization file");
            System.exit(0);
         }

         X509EncodedKeySpec var3 = new X509EncodedKeySpec(var1);
         KeyFactory var4 = KeyFactory.getInstance("RSA");
         this.pubkey = var4.generatePublic(var3);
      } catch (Exception var5) {
         this.error = "Could not deserialize authpub.key";
         MudgeSanity.logException("authpub.key deserialization", var5, false);
      }

   }

   public String error() {
      return this.error;
   }

   public byte[] decrypt(byte[] var1) {
      byte[] var2 = this._decrypt(var1);

      try {
         if (var2.length == 0) {
            return var2;
         } else {
            DataParser var3 = new DataParser(var2);
            var3.big();
            int var4 = var3.readInt();
            if (var4 == -889274181) {
               this.error = "pre-4.0 authorization file. Run update to get new file";
               return new byte[0];
            } else if (var4 != -889274157) {
               this.error = "bad header";
               return new byte[0];
            } else {
               int var5 = var3.readShort();
               byte[] var6 = var3.readBytes(var5);
               return var6;
            }
         }
      } catch (Exception var7) {
         this.error = var7.getMessage();
         return new byte[0];
      }
   }

   protected byte[] _decrypt(byte[] var1) {
      byte[] var2 = new byte[0];

      try {
         if (this.pubkey == null) {
            return new byte[0];
         } else {
            synchronized(this.cipher) {
               this.cipher.init(2, this.pubkey);
               var2 = this.cipher.doFinal(var1);
            }

            return var2;
         }
      } catch (Exception var6) {
         this.error = var6.getMessage();
         return new byte[0];
      }
   }
}
