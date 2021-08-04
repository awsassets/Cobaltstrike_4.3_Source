package c2profile;

import beacon.setup.ProcessInject;
import cloudstrike.NanoHTTPD;
import cloudstrike.Response;
import common.Authorization;
import common.CommonUtils;
import common.License;
import common.MudgeSanity;
import common.SleevedResource;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import net.jsign.DigestAlgorithm;
import net.jsign.timestamp.TimestampingMode;
import pe.BeaconRDLL;
import pe.MalleablePE;
import pe.PEParser;

public class Lint {
   public static final int PROGRAM_TRANSFORM = 0;
   public static final int PROGRAM_RECOVER = 1;
   protected Profile prof;
   protected String uri = "";
   protected Map headers = new HashMap();

   public Lint(Profile var1) {
      this.prof = var1;
   }

   public void bounds(String var1, int var2, int var3) {
      int var4 = CommonUtils.toNumber(this.prof.getString(var1), 0);
      if (var4 < var2) {
         CommonUtils.print_error("Option " + var1 + " is " + var4 + "; less than lower bound of " + var2);
      }

      if (var4 > var3) {
         CommonUtils.print_error("Option " + var1 + " is " + var4 + "; greater than upper bound of " + var3);
      }

   }

   public void boundsLen(String var1, int var2) throws Exception {
      String var3 = this.prof.getString(var1);
      if (var3.length() > var2) {
         CommonUtils.print_error("Length of option " + var1 + " is " + var3.length() + "; greater than upper bound of " + var2);
      }

   }

   public void checkPipeValue(String var1, String var2, int var3, boolean var4) {
      if (!var4) {
         if (var2.length() > var3) {
            CommonUtils.print_error("Length of " + var1 + " option \"" + var2 + "\" is " + var2.length() + "; greater than upper bound of " + var3);
         }

         if (CommonUtils.toSet(var2).size() > 1) {
            CommonUtils.print_error("Option " + var1 + " only allows one value. You have " + CommonUtils.toSet(var2).size());
         }

         if ("".equals(var2)) {
            CommonUtils.print_error("Woah! " + var1 + " is empty. That's going to break anything that tries to use this pipe value.");
         }

         if (var2.startsWith("\\\\.\\pipe\\")) {
            CommonUtils.print_error(var1 + " should not start with \\\\.\\pipe\\. You're specifying the stuff after this path.");
         }
      } else {
         Iterator var5 = CommonUtils.toSet(var2).iterator();

         while(var5.hasNext()) {
            this.checkPipeValue(var1, (String)var5.next(), var3, false);
         }
      }

   }

   public void checkPipe(String var1, int var2, boolean var3) {
      this.checkPipeValue(var1, this.prof.getString(var1), var2, var3);
   }

   public byte[] randomData(int var1) {
      Random var2 = new Random();
      byte[] var3 = new byte[var1];
      var2.nextBytes(var3);
      return var3;
   }

   public void verb_compatability() {
      if ("GET".equals(this.prof.getString(".http-get.verb")) && this.prof.posts(".http-get.client.metadata")) {
         CommonUtils.print_error(".http-get.verb is GET, but .http-get.client.metadata needs POST");
      }

      if ("GET".equals(this.prof.getString(".http-post.verb"))) {
         if (this.prof.posts(".http-post.client.id")) {
            CommonUtils.print_error(".http-post.verb is GET, but .http-post.client.id needs POST");
         }

         if (this.prof.posts(".http-post.client.output")) {
            CommonUtils.print_error(".http-post.verb is GET, but .http-post.client.output needs POST");
         }
      }

   }

   public void safetylen(String var1, String var2, Map var3) {
      Iterator var4 = var3.entrySet().iterator();

      while(var4.hasNext()) {
         Entry var5 = (Entry)var4.next();
         String var6 = var5.getValue() + "";
         if (var6.length() > 1024) {
            CommonUtils.print_error(var2 + " " + var1 + " '" + var5.getKey() + "' is " + var6.length() + " bytes [should be <1024 bytes]");
         }
      }

   }

   public void safetyuri(String var1, String var2, Map var3) {
      StringBuffer var4 = new StringBuffer();
      var4.append(this.uri + var2 + "?");
      Iterator var5 = var3.entrySet().iterator();

      while(var5.hasNext()) {
         Entry var6 = (Entry)var5.next();
         String var7 = var6.getKey() + "";
         String var8 = var6.getValue() + "";
         var4.append(var7 + "=" + var8);
      }

      if (var4.toString().length() > 1024) {
         CommonUtils.print_error(var1 + " URI line (uri + parameters) is " + var4.toString().length() + " bytes [should be <1024 bytes]");
      }

   }

   public void testuri(String var1, String var2, int var3) {
      if (var2.length() > var3) {
         CommonUtils.print_error(var1 + " is too long! " + var2.length() + " bytes [should be <=" + var3 + " bytes]");
      }

      if (var2.indexOf("?") >= 0) {
         CommonUtils.print_error(var1 + " '" + var2 + "' should not contain a ?");
      }

      if (!var2.startsWith("/")) {
         CommonUtils.print_error(var1 + " '" + var2 + "' must start with a /");
      }

   }

   public void testuri_stager(String var1) {
      String var2 = this.prof.getString(var1);
      String var3 = this.prof.getQueryString(".http-stager.client");
      if (!"".equals(var2)) {
         this.testuri(var1, var2, 79);
      } else {
         var2 = CommonUtils.MSFURI();
      }

      if (!"".equals(var3)) {
         var2 = var2 + "?" + var3;
         if (var2.length() > 79) {
            CommonUtils.print_error(var1 + " URI line (uri + parameters) is " + var2.toString().length() + " bytes [should be <80 bytes]");
         }
      }

   }

   public void testuri(String var1) {
      int var2 = 0;
      String[] var3 = this.prof.getString(var1 + ".uri").split(" ");

      for(int var4 = 0; var4 < var3.length; ++var4) {
         if (var3[var4].length() > var2) {
            this.uri = var3[var4];
            var2 = var3[var4].length();
         }

         this.testuri(var1 + ".uri", var3[var4], 63);
      }

   }

   public void testuriCompare(String var1, String var2) {
      LintURI var3 = new LintURI();
      var3.add_split(var1, this.prof.getString(var1));
      var3.add_split(var2, this.prof.getString(var2));
      var3.add(".http-stager.uri_x86", this.prof.getString(".http-stager.uri_x86"));
      var3.add(".http-stager.uri_x64", this.prof.getString(".http-stager.uri_x64"));
      var3.checks();
   }

   public boolean test(String var1, String var2, int var3) throws Exception {
      return this.test(var1, var2, var3, false);
   }

   public boolean test(String var1, String var2, int var3, boolean var4) throws Exception {
      Response var5 = new Response("200 OK", (String)null, (InputStream)null);
      byte[] var6 = this.randomData(var3);
      byte[] var7 = Arrays.copyOf(var6, var6.length);
      if (var2.equals(".id")) {
         var6 = "1234".getBytes("UTF-8");
         var7 = Arrays.copyOf(var6, var6.length);
      }

      if (var4) {
         this.prof.apply(var1, var5, var7);
      } else {
         this.prof.apply(var1 + var2, var5, var7);
      }

      byte[] var8;
      if (var5.data != null) {
         var8 = new byte[var5.data.available()];
         var5.data.read(var8, 0, var8.length);
      } else {
         var8 = new byte[0];
      }

      this.safetyuri(var1, var5.uri, var5.params);
      this.safetylen("parameter", var1, var5.params);
      this.safetylen("header", var1, var5.header);
      String var9 = this.prof.recover(var1 + var2, var5.header, var5.params, new String(var8, "ISO8859-1"), var5.uri);
      byte[] var10 = Program.toBytes(var9);
      if (!Arrays.equals(var10, var6)) {
         CommonUtils.print_error(var1 + var2 + " transform+recover FAILED (" + var3 + " byte[s])");
         return false;
      } else {
         Iterator var11 = var5.params.entrySet().iterator();

         Entry var12;
         String var13;
         String var14;
         while(var11.hasNext()) {
            var12 = (Entry)var11.next();
            var13 = var12.getKey() + "";
            var14 = var12.getValue() + "";
            var12.setValue(URLEncoder.encode(var12.getValue() + "", "UTF-8"));
         }

         var11 = var5.header.entrySet().iterator();

         do {
            if (!var11.hasNext()) {
               var9 = this.prof.recover(var1 + var2, var5.header, var5.params, new String(var8, "ISO8859-1"), var5.uri);
               var10 = Program.toBytes(var9);
               if (!Arrays.equals(var10, var6)) {
                  CommonUtils.print_error(var1 + var2 + " transform+mangle+recover FAILED (" + var3 + " byte[s]) - encode your data!");
                  return false;
               }

               CommonUtils.print_good(var1 + var2 + " transform+mangle+recover passed (" + var3 + " byte[s])");
               return true;
            }

            var12 = (Entry)var11.next();
            var13 = var12.getKey() + "";
            var14 = var12.getValue() + "";
            var12.setValue(var14.replaceAll("\\P{Graph}", ""));
            if (".http-get.server".equals(var1)) {
               this.headers.put(var13.toLowerCase(), var14.toLowerCase());
            }
         } while(!var1.endsWith(".client") || !"cookie".equals(var13.toLowerCase()) || !this.prof.option(".http_allow_cookies"));

         CommonUtils.print_error(var1 + var2 + " uses HTTP cookie header, but http_allow_cookies is set to true.");
         return false;
      }
   }

   public boolean checkProgramSizes(String var1, int var2, int var3) throws IOException {
      byte[] var4;
      if (var3 == 0) {
         var4 = this.prof.apply_binary(var1);
      } else {
         var4 = this.prof.recover_binary(var1);
      }

      if (var4.length < var2) {
         return true;
      } else {
         CommonUtils.print_error("Program " + var1 + " size check failed.\n\tProgram " + var1 + " must have a compiled size less than " + var2 + " bytes. Current size is: " + var4.length);
         return false;
      }
   }

   public boolean checkPost3x() throws IOException {
      int var1 = this.prof.size(".http-post.client.output", 2097152);
      if (var1 < 6291456) {
         return true;
      } else {
         CommonUtils.print_error("POST 3x check failed.\n\tEncoded HTTP POST must be less than 3x size of non-encoded post. Tested: 2097152 bytes; received " + var1 + " bytes");
         return false;
      }
   }

   public void checkHeaders() {
      if ("chunked".equals(this.headers.get("transfer-encoding"))) {
         CommonUtils.print_error("Remove 'Transfer-Encoding: chunked' header. It will interfere with C2.");
      }

   }

   public void checkHttpConfig() {
      Map var1 = this.prof.getHeadersAsMap(".http-config");
      Set var2 = CommonUtils.toSet("Content-Length, Date, Content-Type");
      Iterator var3 = var2.iterator();

      String var4;
      while(var3.hasNext()) {
         var4 = (String)var3.next();
         if (var1.containsKey(var4)) {
            CommonUtils.print_error(".http-config should not set header '" + var4 + "'. Let the web server set the value for this field.");
         }
      }

      var4 = this.prof.getString(".http-config.block_useragents");
      if (!"".equals(var4)) {
         String[] var5 = var4.split(",");
         int var6 = 0;
         String[] var7 = var5;
         int var8 = var5.length;

         for(int var9 = 0; var9 < var8; ++var9) {
            String var10 = var7[var9];
            ++var6;
            var10 = var10.trim();
            if (var10.length() == 0) {
               CommonUtils.print_error(".http-config.block_useragents (comma separated list) has a blank value for item #" + var6);
            }
         }
      }

   }

   public void checkCollissions(String var1) {
      Program var2 = this.prof.getProgram(var1);
      if (var2 != null) {
         List var3 = var2.collissions(this.prof);
         Iterator var4 = var3.iterator();

         while(var4.hasNext()) {
            String var5 = (String)var4.next();
            CommonUtils.print_error(var1 + " collission for " + var5);
         }

      }
   }

   public void checkKeystore() {
      try {
         KeyStore var1 = KeyStore.getInstance("JKS");
         var1.load(this.prof.getSSLKeystore(), this.prof.getSSLPassword().toCharArray());
         KeyManagerFactory var2 = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
         var2.init(var1, this.prof.getSSLPassword().toCharArray());
         SSLContext var3 = SSLContext.getInstance("SSL");
         var3.init(var2.getKeyManagers(), new TrustManager[]{new NanoHTTPD.TrustEverything()}, new SecureRandom());
         SSLServerSocketFactory var4 = var3.getServerSocketFactory();
      } catch (Exception var5) {
         CommonUtils.print_error("Could not load SSL keystore: " + var5.getMessage());
      }

   }

   public void checkCodeSigner() {
      if ("".equals(this.prof.getString(".code-signer.alias"))) {
         CommonUtils.print_error(".code-signer.alias is empty. This is the keystore alias for your imported code signing cert");
      }

      if ("".equals(this.prof.getString(".code-signer.password"))) {
         CommonUtils.print_error(".code-signer.password is empty. This is the keystore password");
      }

      String var1;
      if (!"".equals(this.prof.getString(".code-signer.digest_algorithm"))) {
         var1 = this.prof.getString(".code-signer.digest_algorithm");

         try {
            DigestAlgorithm.valueOf(var1);
         } catch (Exception var7) {
            CommonUtils.print_error(".code-sign.digest_algorithm '" + var1 + "' is not valid. (Acceptable values: " + CommonUtils.joinObjects(DigestAlgorithm.values(), ", ") + ")");
         }
      }

      if (!"".equals(this.prof.getString(".code-signer.timestamp_mode"))) {
         var1 = this.prof.getString(".code-signer.timestamp_mode");

         try {
            TimestampingMode.valueOf(var1);
         } catch (Exception var6) {
            CommonUtils.print_error(".code-sign.timestamp_mode '" + var1 + "' is not valid. (Acceptable values: " + CommonUtils.joinObjects(TimestampingMode.values(), ", ") + ")");
         }
      }

      var1 = this.prof.getString(".code-signer.keystore");
      String var2 = this.prof.getString(".code-signer.password");
      String var3 = this.prof.getString(".code-signer.alias");

      try {
         KeyStore var4 = KeyStore.getInstance("JKS");
         var4.load(new FileInputStream(var1), var2.toCharArray());
      } catch (Exception var5) {
         CommonUtils.print_error(".code-signer.keystore failed to load keystore: " + var5.getMessage());
      }

   }

   public void checkMZ(String var1) {
      BeaconRDLL var2 = new BeaconRDLL(this.prof, var1);
      int var3 = var2.getPatch(0).length;
      if (var3 >= 60) {
         CommonUtils.print_error(".stage.magic_mz_" + var1 + " and patch is " + var3 + " bytes. Reduce its size to <60b.");
      }

      byte[] var4 = this.prof.getStringAsBytes(".stage.magic_mz_" + var1);
      if (var4.length < 2) {
         CommonUtils.print_error(".stage.magic_mz_" + var1 + " is <2 bytes. :( What am I supposed to use to identify the beginning of the DLL?");
      }

   }

   public void checkPE() {
      try {
         PEParser var1 = PEParser.load(SleevedResource.readResource("resources/beacon.dll"));
         int var2 = this.prof.getInt(".stage.image_size_x86");
         int var3 = var1.get("SizeOfImage");
         if (var2 > 0 && var2 < var3) {
            CommonUtils.print_error(".stage.image_size_x86 must be larger than " + var3 + " bytes");
         }

         PEParser var4 = PEParser.load(SleevedResource.readResource("resources/beacon.x64.dll"));
         int var5 = this.prof.getInt(".stage.image_size_x64");
         int var6 = var4.get("SizeOfImage");
         if (var5 > 0 && var5 < var6) {
            CommonUtils.print_error(".stage.image_size_x64 must be larger than " + var6 + " bytes");
         }

         MalleablePE var7 = new MalleablePE(this.prof);
         byte[] var8 = var7.process(SleevedResource.readResource("resources/beacon.dll"), "x86");
         if (var8.length > 271000) {
            CommonUtils.print_error(".stage.transform-x86 results in a stage that's too large");
         } else if (var8.length == 0) {
            CommonUtils.print_error(".stage.transform-x86 failed (unknown reason)");
         }

         MalleablePE var9 = new MalleablePE(this.prof);
         byte[] var10 = var9.process(SleevedResource.readResource("resources/beacon.x64.dll"), "x64");
         if (var10.length > 271000) {
            CommonUtils.print_error(".stage.transform-x64 results in a stage that's too large");
         } else if (var10.length == 0) {
            CommonUtils.print_error(".stage.transform-x86 failed (unknown reason)");
         }

         String var11 = this.prof.getString(".stage.rich_header");
         if (var11.length() > 256) {
            CommonUtils.print_error(".stage.rich_header is too big. Reduce to <=256 bytes");
         }

         byte[] var12 = this.prof.getToString(".stage").getBytes();
         if (var12.length > 4096) {
            CommonUtils.print_error(".stage added " + var12.length + " bytes of strings. Reduce to <=4096");
         }

         Set var13 = CommonUtils.toSetLC(CommonUtils.readResourceAsString("resources/dlls.x86.txt").split("\n"));
         String var14 = this.prof.getString(".stage.module_x86").toLowerCase();
         if (!"".equals(var14) && var13.contains(var14)) {
            CommonUtils.print_error(".stage.module_x86 stomps '" + var14 + "' needed by x86 Beacon DLL.");
         }

         Set var15 = CommonUtils.toSetLC(CommonUtils.readResourceAsString("resources/dlls.x64.txt").split("\n"));
         String var16 = this.prof.getString(".stage.module_x64").toLowerCase();
         if (!"".equals(var16) && var15.contains(var16)) {
            CommonUtils.print_error(".stage.module_x64 stomps '" + var16 + "' needed by x64 Beacon DLL.");
         }

         if (!"".equals(var14) && var2 > var3) {
            CommonUtils.print_warn(".stage.module_x86 AND .stage.image_size_x86 are defined. Risky! Will " + var14 + " hold ~" + var2 * 2 + " bytes?");
         }

         if (!"".equals(var16) && var5 > var6) {
            CommonUtils.print_warn(".stage.module_x64 AND .stage.image_size_x64 are defined. Risky! Will " + var16 + " hold ~" + var5 * 2 + " bytes?");
         }

         String var17 = this.prof.getString(".stage.allocator");
         boolean var18 = this.prof.option(".stage.userwx");
         if ((!"".equals(var14) || !"".equals(var16)) && !"VirtualAlloc".equals(var17)) {
            CommonUtils.print_error("Set .stage.allocator to VirtualAlloc to module stomp. module_x86/module_x64 ignored otherwise.");
         }

         if (!var18 && "HeapAlloc".equals(var17)) {
            CommonUtils.print_error(".stage.allocator is HeapAlloc AND .stage.userwx=false. HeapAlloc will allocate RWX memory");
         }

         byte[] var19 = this.prof.getStringAsBytes(".stage.magic_pe");
         if (var19.length != 2) {
            CommonUtils.print_error(".stage.magic_pe " + CommonUtils.toHexString(var19) + " must have exactly two characters.");
         }

         this.checkMZ("x86");
         this.checkMZ("x64");
      } catch (Exception var20) {
         MudgeSanity.logException("pe check", var20, false);
      }

   }

   public void sleepMaskCodeCaveCheck(String var1) {
      PEParser var2 = PEParser.load(SleevedResource.readResource(var1));
      int var3 = var2.sectionEnd(".text");
      int var4 = var2.sectionAddress(".rdata") - var3;
      if (var4 < 256) {
         CommonUtils.print_error(".stage.sleep_mask is true; nook space in " + var1 + " is " + var4 + " bytes. Beacon will crash.");
      }

   }

   public void sleepMaskCodeCaveCheck() {
      if (this.prof.option(".stage.sleep_mask")) {
         this.sleepMaskCodeCaveCheck("resources/beacon.dll");
         this.sleepMaskCodeCaveCheck("resources/beacon.x64.dll");
         this.sleepMaskCodeCaveCheck("resources/dnsb.dll");
         this.sleepMaskCodeCaveCheck("resources/dnsb.x64.dll");
         this.sleepMaskCodeCaveCheck("resources/extc2.dll");
         this.sleepMaskCodeCaveCheck("resources/extc2.x64.dll");
         this.sleepMaskCodeCaveCheck("resources/pivot.dll");
         this.sleepMaskCodeCaveCheck("resources/pivot.x64.dll");
      }
   }

   public void checkProcessInject() {
      boolean var1 = this.prof.option(".process-inject.userwx");
      boolean var2 = this.prof.option(".process-inject.startrwx");
      int var3 = this.prof.getInt(".process-inject.min_alloc");
      this.bounds(".process-inject.min_alloc", 0, 268435455);
      ProcessInject var4 = (new ProcessInject(this.prof)).check();
      Iterator var5 = var4.getErrors().iterator();

      while(var5.hasNext()) {
         CommonUtils.print_error((String)var5.next());
      }

      Iterator var6 = var4.getWarnings().iterator();

      while(var6.hasNext()) {
         CommonUtils.print_warn((String)var6.next());
      }

   }

   public void setupProcessInject(String var1) {
      byte[] var2 = this.prof.getPrependedData(".process-inject.transform-" + var1);
      byte[] var3 = this.prof.getAppendedData(".process-inject.transform-" + var1);
      int var4 = var2.length + var3.length;
      if (var4 > 252) {
         CommonUtils.print_error(".process-inject.transform-" + var1 + " is " + var4 + " bytes. Reduce to <=252 bytes");
      }

   }

   public void checkSpawnTo(String var1, String var2, String var3) {
      String var4 = this.prof.getString(var1);
      if (var4.length() > 63) {
         CommonUtils.print_error(var1 + " is too long. Limit to 63 characters");
      }

      if (var4.indexOf("\\") == -1) {
         CommonUtils.print_error(var1 + " should refer to a full path.");
      }

      if (var4.toLowerCase().indexOf("\\system32\\") > -1) {
         CommonUtils.print_error(var1 + " references system32. This will break x86->x64 and x64->x86 spawns");
      }

      if (var4.indexOf(var2) > -1) {
         CommonUtils.print_error(var1 + " references " + var2 + ". For this architecture, probably not what you want");
      }

      if (var4.indexOf(var3) == -1 && var4.toLowerCase().indexOf(var3) > -1) {
         int var5 = var4.toLowerCase().indexOf(var3);
         String var6 = var4.substring(var5, var5 + var3.length());
         CommonUtils.print_error(var1 + ": lowercase '" + var6 + "'. This allows runtime adjustments to work");
      }

      if (var4.indexOf("rundll32.exe") > -1) {
         CommonUtils.print_opsec("[OPSEC] " + var1 + " is '" + var4 + "'. This is a *really* bad OPSEC choice.");
      }

   }

   public static void main(String[] var0) {
      if (var0.length == 0) {
         CommonUtils.print_info("Please specify a Beacon profile file\n\t./c2lint my.profile");
      } else {
         License.checkLicenseConsole(new Authorization());
         Profile var1 = Loader.LoadProfile(var0[0]);
         if (var1 != null) {
            String[] var2 = var1.getVariants();

            for(int var3 = 0; var3 < var2.length; ++var3) {
               Profile var4 = var1.getVariantProfile(var2[var3]);
               checkProfile(var2[var3], var4);
            }

         }
      }
   }

   public static void checkProfile(String var0, Profile var1) {
      try {
         Lint var2 = new Lint(var1);
         if (var1 == null) {
            return;
         }

         StringBuffer var3 = new StringBuffer();
         var3.append("\n\u001b[01;30m");
         var3.append("===============\n");
         var3.append(var0);
         var3.append("\n===============");
         var3.append("\u001b[0m\n\n");
         var3.append("http-get");
         var3.append("\n\u001b[01;30m");
         var3.append("--------");
         var3.append("\n\u001b[01;31m");
         var3.append(var1.getPreview().getClientSample(".http-get"));
         var3.append("\u001b[01;34m");
         var3.append(var1.getPreview().getServerSample(".http-get"));
         var3.append("\u001b[0m\n\n");
         var3.append("http-post");
         var3.append("\n\u001b[01;30m");
         var3.append("---------");
         var3.append("\n\u001b[01;31m");
         var3.append(var1.getPreview().getClientSample(".http-post"));
         var3.append("\u001b[01;34m");
         var3.append(var1.getPreview().getServerSample(".http-post"));
         var3.append("\u001b[0m\n\n");
         if (var1.getProgram(".http-stager") != null) {
            var3.append("http-stager");
            var3.append("\n\u001b[01;30m");
            var3.append("-----------");
            var3.append("\n\u001b[01;31m");
            var3.append(var1.getPreview().getClientSample(".http-stager"));
            var3.append("\u001b[01;34m");
            var3.append(var1.getPreview().getServerSample(".http-stager"));
            var3.append("\u001b[0m\n\n");
         }

         String var4 = ".dns-beacon.dns_stager_subhost";
         String var5 = ".dns-beacon.dns_stager_prepend";
         if (!"".equals(var1.getString(var4))) {
            String var6 = var1.getString(var4);
            var3.append("\ndns staging host");
            var3.append("\n\u001b[01;30m");
            var3.append("----------------");
            var3.append("\n\u001b[01;31m");
            var3.append("aaa" + var6 + "<domain>");
            if (var1.hasString(var5)) {
               var3.append(" = ");
               var3.append(var1.getString(var5));
               var3.append("[...]");
            }

            var3.append("\n");
            var3.append("bdc" + var6 + "<domain>");
            var3.append("\u001b[0m\n");
         }

         System.out.println(var3.toString());
         checkDNSBeacon(DNSBeaconAction.PREVIEW, var2, var1);
         if (var2.checkPost3x()) {
            CommonUtils.print_good("POST 3x check passed");
         }

         if (var2.checkProgramSizes(".http-get.server.output", 252, 1)) {
            CommonUtils.print_good(".http-get.server.output size is good");
         }

         if (var2.checkProgramSizes(".http-get.client", 508, 0)) {
            CommonUtils.print_good(".http-get.client size is good");
         }

         if (var2.checkProgramSizes(".http-post.client", 508, 0)) {
            CommonUtils.print_good(".http-post.client size is good");
         }

         var2.testuri(".http-get");
         var2.test(".http-get.client", ".metadata", 1, true);
         var2.test(".http-get.client", ".metadata", 100, true);
         var2.test(".http-get.client", ".metadata", 128, true);
         var2.test(".http-get.client", ".metadata", 256, true);
         var2.test(".http-get.server", ".output", 0, true);
         var2.test(".http-get.server", ".output", 1, true);
         var2.test(".http-get.server", ".output", 48248, true);
         var2.test(".http-get.server", ".output", 1048576, true);
         var2.testuri(".http-post");
         var2.test(".http-post.client", ".id", 4);
         var2.test(".http-post.client", ".output", 0);
         var2.test(".http-post.client", ".output", 1);
         if (var1.shouldChunkPosts()) {
            CommonUtils.print_good(".http-post.client.output chunks results");
            var2.test(".http-post.client", ".output", 33);
            var2.test(".http-post.client", ".output", 128);
         } else {
            CommonUtils.print_good(".http-post.client.output POSTs results");
            var2.test(".http-post.client", ".output", 48248);
            var2.test(".http-post.client", ".output", 1048576);
         }

         if (Profile.usesCookieBeacon(var1)) {
            CommonUtils.print_good("Beacon profile specifies an HTTP Cookie header. Will tell WinINet to allow this.");
         }

         if (var1.usesCookie(".http-stager.client")) {
            CommonUtils.print_good("Stager profile specifies an HTTP Cookie header. Will tell WinINet to allow this.");
         }

         if (Profile.usesHostBeacon(var1)) {
            CommonUtils.print_warn("Profile uses HTTP Host header for C&C. Will ignore Host header specified in payload config.");
         }

         var2.verb_compatability();
         var2.testuri_stager(".http-stager.uri_x86");
         var2.testuri_stager(".http-stager.uri_x64");
         String var8 = var1.getHeaders(".http-stager.client", "");
         if (var8.length() > 303) {
            CommonUtils.print_error(".http-stager.client headers are " + var8.length() + " bytes. Max length is 303 bytes");
         }

         int var9 = (int)var1.getHTTPContentOffset(".http-stager.server");
         if (var9 > 0) {
            if ("".equals(var1.getString(".http-stager.uri_x86"))) {
               CommonUtils.print_error(".http-stager.uri_x86 is not defined.");
            }

            if ("".equals(var1.getString(".http-stager.uri_x64"))) {
               CommonUtils.print_error(".http-stager.uri_x64 is not defined.");
            }
         }

         if (var9 > 65535) {
            CommonUtils.print_error(".http-stager.server.output prepend value is " + var9 + " bytes. Max is 65535. HTTP/S Stagers will crash");
         }

         var2.bounds(".sleeptime", 1, Integer.MAX_VALUE);
         var2.bounds(".jitter", 0, 99);
         int var10 = var1.getInt(".data_jitter");
         if (var10 != 0) {
            var2.bounds(".data_jitter", 10, Integer.MAX_VALUE);
         }

         short var11 = 10000;
         if (var10 > var11) {
            CommonUtils.print_warn(".data_jitter value (" + var10 + ") exceeds recommended limit (" + var11 + "). Excessive jitter could impact HTTP beacon latency and general team server performance.");
         }

         var2.testuriCompare(".http-get.uri", ".http-post.uri");
         var2.boundsLen(".spawnto", 63);
         var2.boundsLen(".useragent", 255);
         var2.checkPipe(".pipename", 64, false);
         var2.checkPipe(".pipename_stager", 64, false);
         var2.checkPipe(".ssh_pipename", 64, true);
         var2.checkPipe(".post-ex.pipename", 48, true);
         var2.boundsLen(".ssh_banner", 120);
         var2.boundsLen(".smb_frame_header", 124);
         var2.boundsLen(".tcp_frame_header", 124);
         if (var1.getString(".pipename").equals(var1.getString(".pipename_stager"))) {
            CommonUtils.print_error(".pipename and .pipename_stager are the same. Make these different strings.");
         }

         var2.checkHeaders();
         var2.checkHttpConfig();
         var1.getHeadersToRemove();
         var2.checkCollissions(".http-get.client");
         var2.checkCollissions(".http-get.server");
         var2.checkCollissions(".http-post.client");
         var2.checkCollissions(".http-post.server");
         var2.checkCollissions(".http-stager.client");
         var2.checkCollissions(".http-stager.server");
         if (!var1.option(".host_stage")) {
            CommonUtils.print_warn(".host_stage is FALSE. This will break staging over HTTP, HTTPS, and DNS!");
         } else {
            CommonUtils.print_opsec("[OPSEC] .host_stage is true. Your Beacon payload is available to anyone that connects to your server to request it. Are you OK with this? ");
         }

         if (!"rundll32.exe".equals(var1.getString(".spawnto"))) {
            CommonUtils.print_error(".spawnto is deprecated and has no effect. Set .post-ex.spawnto_x86 and .post-ex.spawnto_x64 instead.");
         }

         if (!"%windir%\\syswow64\\rundll32.exe".equals(var1.getString(".spawnto_x86"))) {
            CommonUtils.print_error(".spawnto_x86 is deprecated and has no effect. Set .post-ex.spawnto_x86 instead.");
         }

         if (!"%windir%\\sysnative\\rundll32.exe".equals(var1.getString(".spawnto_x64"))) {
            CommonUtils.print_error(".spawnto_x64 is deprecated and has no effect. Set .post-ex.spawnto_x64 instead.");
         }

         if (var1.option(".amsi_disable")) {
            CommonUtils.print_error(".amsi_disable is deprecated and has no effect. Set .post-ex.amsi_disable instead.");
         }

         var2.checkSpawnTo(".post-ex.spawnto_x86", "sysnative", "syswow64");
         var2.checkSpawnTo(".post-ex.spawnto_x64", "syswow64", "sysnative");
         if (var1.isFile(".code-signer.keystore")) {
            CommonUtils.print_good("Found code-signing configuration. Will sign executables and DLLs");
            var2.checkCodeSigner();
         } else {
            CommonUtils.print_warn(".code-signer.keystore is missing. Will not sign executables and DLLs");
         }

         var2.boundsLen(".post-ex.thread_hint", 58);
         if (var1.isFile(".https-certificate.keystore")) {
            CommonUtils.print_good("Found SSL certificate keystore");
            if (var1.getSSLPassword() != null && var1.getSSLPassword().length() != 0) {
               if ("123456".equals(var1.getSSLPassword())) {
                  CommonUtils.print_warn(".https-certificate.password is the default '123456'. Is this really your keystore password?");
               }
            } else {
               CommonUtils.print_error(".https-certificate.password is empty. A password is required for your keystore.");
            }
         } else if (var1.regenerateKeystore()) {
            if (var1.getSSLKeystore() != null) {
               CommonUtils.print_good("SSL certificate generation OK");
            }
         } else {
            CommonUtils.print_opsec("[OPSEC] .https-certificate options are missing [will use built-in SSL cert]");
         }

         var2.checkKeystore();
         var2.checkPE();
         var2.sleepMaskCodeCaveCheck();
         if (!"".equals(var1.getString(".maxdns"))) {
            CommonUtils.print_error(".maxdns is deprecated and has no effect. Set .dns-beacon.maxdns instead.");
         }

         if (!"".equals(var1.getString(".dns_max_txt"))) {
            CommonUtils.print_error(".dns_max_txt is deprecated and has no effect. Set .dns-beacon.dns_max_txt instead.");
         }

         if (!"".equals(var1.getString(".dns_ttl"))) {
            CommonUtils.print_error(".dns_ttl is deprecated and has no effect. Set .dns-beacon.dns_ttl instead.");
         }

         if (!"".equals(var1.getString(".dns_sleep"))) {
            CommonUtils.print_error(".dns_sleep is deprecated and has no effect. Set .dns-beacon.dns_sleep instead.");
         }

         if (!"".equals(var1.getString(".dns_idle"))) {
            CommonUtils.print_error(".dns_idle is deprecated and has no effect. Set .dns-beacon.dns_idle instead.");
         }

         if (!"".equals(var1.getString(".dns_stager_subhost"))) {
            CommonUtils.print_error(".dns_stager_subhost is deprecated and has no effect. Set .dns-beacon.dns_stager_subhost instead.");
         }

         if (!"".equals(var1.getString(".dns_stager_prepend"))) {
            CommonUtils.print_error(".dns_stager_prepend is deprecated and has no effect. Set .dns-beacon.dns_stager_prepend instead.");
         }

         checkDNSBeacon(DNSBeaconAction.VALIDATE, var2, var1);
         if (!var1.option(".create_remote_thread")) {
            CommonUtils.print_warn(".create_remote_thread is deprecated and has no effect.");
         }

         if (!var1.option(".hijack_remote_thread")) {
            CommonUtils.print_warn(".hijack_remote_thread is deprecated and has no effect.");
         }

         var2.setupProcessInject("x86");
         var2.setupProcessInject("x64");
         var2.checkProcessInject();
      } catch (Exception var7) {
         var7.printStackTrace();
      }

   }

   private static void checkDNSBeacon(DNSBeaconAction var0, Lint var1, Profile var2) throws Exception {
      String var3 = ".dns-beacon";
      var1.bounds(var3 + ".maxdns", 1, 255);
      var1.bounds(var3 + ".dns_max_txt", 4, 252);
      var1.bounds(var3 + ".dns_ttl", 1, Integer.MAX_VALUE);
      if (var2.getInt(var3 + ".dns_ttl") >= 30) {
         CommonUtils.print_warn(var3 + ".dns_ttl is " + var2.getInt(var3 + ".dns_ttl") + " seconds. Each of your Beacon checkins will cache/delay for this time.");
      }

      int var4 = Integer.parseInt(var2.getString(var3 + ".dns_max_txt"));
      if (var4 % 4 != 0) {
         CommonUtils.print_error(var3 + ".dns_max_txt value (" + var4 + ") must be divisible by four.");
      }

      String var5 = var3 + ".dns_stager_subhost";
      String var6;
      if (!"".equals(var2.getString(var5))) {
         var6 = var2.getString(var5);
         if (!var6.endsWith(".")) {
            CommonUtils.print_error(var5 + " must end with a '.' (it's prepended to a parent domain)");
         }

         if (var6.length() > 32) {
            CommonUtils.print_error(var5 + " is too long. Keep it under 32 characters.");
         }

         if (var6.indexOf("..") > -1) {
            CommonUtils.print_error(var5 + " contains '..'. This is not valid in a hostname");
         }
      }

      var6 = var3 + ".ns_response";
      String var7 = var2.getString(var6);
      if (!"".equals(var7) && !"drop".equals(var7) && !"idle".equals(var7) && !"zero".equals(var7)) {
         CommonUtils.print_error(var6 + " must be blank, 'drop', 'idle', or 'zero'.");
      }

      String var8 = var3 + ".beacon";
      String var9 = var2.getString(var8);
      String var10 = var3 + ".get_A";
      String var11 = var2.getString(var10);
      String var12 = var3 + ".get_AAAA";
      String var13 = var2.getString(var12);
      String var14 = var3 + ".get_TXT";
      String var15 = var2.getString(var14);
      String var16 = var3 + ".put_metadata";
      String var17 = var2.getString(var16);
      String var18 = var3 + ".put_output";
      String var19 = var2.getString(var18);
      switch(var0) {
      case VALIDATE:
         if (!"".equals(var9)) {
            cannotBe(".", var8, var9);
            cannotStartWith(".", var8, var9);
            noAdjacentPeriods(var8, var9);
            noWhitespace(var8, var9);
            validHostnameCharsOnly(var8, var9);
            validateHostnameSegments(var8, var9);
            var1.boundsLen(var8, 32);
            lastSegmentMaxLen(var8, var9, 32);
            hostnameLengthWarning(var8, var9, 0, 8);
         }

         checkDNSGetIndicator(var1, var2, var10, var11, var8, var9);
         checkDNSGetIndicator(var1, var2, var12, var13, var8, var9);
         checkDNSGetIndicator(var1, var2, var14, var15, var8, var9);
         checkDNSPutIndicator(var1, var2, var16, var17);
         checkDNSPutIndicator(var1, var2, var18, var19);
         String var20 = ccDefault(var11, "cdn.");
         String var21 = ccDefault(var13, "www6.");
         String var22 = ccDefault(var15, "api.");
         String var23 = ccDefault(var17, "www.");
         String var24 = ccDefault(var19, "post.");
         hostnameCollision(var10, var20, var12, var21);
         hostnameCollision(var10, var20, var14, var22);
         hostnameCollision(var10, var20, var16, var23);
         hostnameCollision(var10, var20, var18, var24);
         hostnameCollision(var12, var21, var14, var22);
         hostnameCollision(var12, var21, var16, var23);
         hostnameCollision(var12, var21, var18, var24);
         hostnameCollision(var14, var22, var16, var23);
         hostnameCollision(var14, var22, var18, var24);
         hostnameCollision(var16, var23, var18, var24);
         break;
      case PREVIEW:
         StringBuffer var25 = new StringBuffer();
         String var26 = "freepics.losenolove.com.";
         String var27 = "aaaaaaaa.";
         String var28 = "bbbbbbbbb.";
         String var29 = "(data).(data).(data).(data).";
         if (!"".equals(var9)) {
            var25.append(previewHeader(var8, var9));
            var25.append("\n" + bracketed(var8) + var27 + var26);
            var25.append("\n" + var9 + var27 + var26);
            var25.append(previewFooter());
            System.out.println(var25.toString());
         }

         if (!"".equals(var11)) {
            var25.delete(0, var25.length());
            var25.append(previewHeader(var10, var11));
            var25.append("\n" + bracketed(var10) + var28 + var27 + var26);
            var25.append("\n" + var11 + var28 + var27 + var26);
            var25.append(previewFooter());
            System.out.println(var25.toString());
         }

         if (!"".equals(var13)) {
            var25.delete(0, var25.length());
            var25.append(previewHeader(var12, var13));
            var25.append("\n" + bracketed(var12) + var28 + var27 + var26);
            var25.append("\n" + var13 + var28 + var27 + var26);
            var25.append(previewFooter());
            System.out.println(var25.toString());
         }

         if (!"".equals(var15)) {
            var25.delete(0, var25.length());
            var25.append(previewHeader(var14, var15));
            var25.append("\n" + bracketed(var14) + var28 + var27 + var26);
            var25.append("\n" + var15 + var28 + var27 + var26);
            var25.append(previewFooter());
            System.out.println(var25.toString());
         }

         if (!"".equals(var17)) {
            var25.delete(0, var25.length());
            var25.append(previewHeader(var16, var17));
            var25.append("\n" + bracketed(var16) + var29 + var28 + var27 + var26);
            var25.append("\n" + var17 + var29 + var28 + var27 + var26);
            var25.append(previewFooter());
            System.out.println(var25.toString());
         }

         if (!"".equals(var19)) {
            var25.delete(0, var25.length());
            var25.append(previewHeader(var18, var19));
            var25.append("\n" + bracketed(var18) + var29 + var28 + var27 + var26);
            var25.append("\n" + var19 + var29 + var28 + var27 + var26);
            var25.append(previewFooter());
            System.out.println(var25.toString());
         }
      }

   }

   private static String ccDefault(String var0, String var1) {
      return "".equals(var0) ? var1 : var0;
   }

   private static void checkDNSGetIndicator(Lint var0, Profile var1, String var2, String var3, String var4, String var5) throws Exception {
      if (!"".equals(var3)) {
         cannotBe(".", var2, var3);
         cannotStartWith(".", var2, var3);
         noAdjacentPeriods(var2, var3);
         noWhitespace(var2, var3);
         validHostnameCharsOnly(var2, var3);
         validateHostnameSegments(var2, var3);
         var0.boundsLen(var2, 32);
         lastSegmentMaxLen(var2, var3, 32);
         hostnameLengthWarning(var2, var3, 2, 8);
      }

   }

   private static String bracketed(String var0) {
      return "[" + var0 + "]";
   }

   private static String previewHeader(String var0, String var1) {
      StringBuffer var2 = new StringBuffer();
      var2.append("\u001b[0m");
      var2.append("" + var0 + " = '" + var1 + "'");
      var2.append("\u001b[01;30m");
      var2.append("\n--------------------------------------------------------");
      var2.append("\u001b[01;31m");
      return var2.toString();
   }

   private static String previewFooter() {
      return "\u001b[0m\n";
   }

   private static void checkDNSPutIndicator(Lint var0, Profile var1, String var2, String var3) throws Exception {
      if (!"".equals(var3)) {
         cannotBe(".", var2, var3);
         cannotStartWith(".", var2, var3);
         noAdjacentPeriods(var2, var3);
         noWhitespace(var2, var3);
         validHostnameCharsOnly(var2, var3);
         validateHostnameSegments(var2, var3);
         var0.boundsLen(var2, 32);
         lastSegmentMaxLen(var2, var3, 6);
         hostnameLengthWarning(var2, var3, 2, 8);
      }

   }

   private static void cannotBeBlank(String var0, String var1) {
      if (var1 == null || var1.length() == 0) {
         CommonUtils.print_error(var0 + " cannot be blank");
      }

   }

   private static void cannotBe(String var0, String var1, String var2) {
      if (var2.equalsIgnoreCase(var0)) {
         CommonUtils.print_error(var1 + " cannot be '" + var0 + "'");
      }

   }

   private static void cannotStartWith(String var0, String var1, String var2) {
      if (var2.startsWith(var0)) {
         CommonUtils.print_error(var1 + " cannot start with '" + var0 + "'");
      }

   }

   private static void noAdjacentPeriods(String var0, String var1) {
      if (var1.indexOf("..") > -1) {
         CommonUtils.print_error(var0 + " must not have adjacent periods ('..')");
      }

   }

   private static void noWhitespace(String var0, String var1) {
      if (var1.matches(".*\\s.*")) {
         CommonUtils.print_error(var0 + " value contains one or more spaces or other whitespace characters");
      }

   }

   private static void validHostnameCharsOnly(String var0, String var1) {
      Pattern var2 = Pattern.compile("^[a-zA-Z0-9._-]*$");
      if (!var2.matcher(var1).find()) {
         CommonUtils.print_error(var0 + " contains invalid characters. Valid characters are alphabetic (a-z and A-Z), numeric(0-9), dash (-), period (.), and underscore (_).");
      }

   }

   private static void lastSegmentMaxLen(String var0, String var1, int var2) {
      if (!var1.endsWith(".")) {
         String[] var3 = var1.split("\\.");
         if (var3.length > 0 && var3[var3.length - 1].length() > var2) {
            CommonUtils.print_error(var0 + " last segment value (" + var3[var3.length - 1] + ") is longer than " + var2 + " characters (appending with other data may exceed hostname syntax rules)");
         }

      }
   }

   private static void validateHostnameSegments(String var0, String var1) {
      byte var2 = 63;
      int var3 = 0;
      String[] var4 = var1.split("\\.");
      String[] var5 = var4;
      int var6 = var4.length;

      for(int var7 = 0; var7 < var6; ++var7) {
         String var8 = var5[var7];
         ++var3;
         if (var8.length() > var2) {
            CommonUtils.print_error(var0 + " segment #" + var3 + " is longer than " + var2 + " characters");
         }
      }

   }

   private static void hostnameLengthWarning(String var0, String var1, int var2, int var3) {
      if (var1.length() < var2) {
         CommonUtils.print_warn(var0 + " is shorter than recommended " + var2 + " character minimum. This prefix value is intended to distinguish CS requests from other data.");
      }

      if (var1.length() > var3) {
         CommonUtils.print_warn(var0 + " is longer than recommended " + var3 + " character maximum. The more indicator characters added, the less data space available...");
      }

   }

   private static void hostnameCollision(String var0, String var1, String var2, String var3) {
      if (var1.length() != 0 && var3.length() != 0) {
         if (var1.equalsIgnoreCase(var3)) {
            CommonUtils.print_error(var0 + " value (" + var1 + ") matches " + var2 + " value");
         } else if (var1.startsWith(var3)) {
            CommonUtils.print_error(var0 + " value (" + var1 + ") starts with " + var2 + " value (" + var3 + "). Overlapping values can cause DNS requests to fail.");
         } else if (var3.startsWith(var1)) {
            CommonUtils.print_error(var2 + " value (" + var3 + ") starts with " + var0 + " value (" + var1 + "). Overlapping values can cause DNS requests to fail.");
         }
      }
   }

   private static enum DNSBeaconAction {
      PREVIEW,
      VALIDATE;
   }
}
