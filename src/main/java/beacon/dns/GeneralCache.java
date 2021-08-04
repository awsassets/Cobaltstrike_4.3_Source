package beacon.dns;

import common.CommonUtils;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class GeneralCache {
   protected Map checks = new HashMap();
   protected long purged = System.currentTimeMillis();

   public static final boolean elapsed(long var0, long var2) {
      long var4 = System.currentTimeMillis() - var0;
      return var4 > var2;
   }

   public boolean contains(String var1) {
      synchronized(this) {
         return this.checks.containsKey(var1);
      }
   }

   public Object get(String var1) {
      synchronized(this) {
         Entry var3 = (Entry)this.checks.get(var1);
         return var3 == null ? null : var3.get();
      }
   }

   public void remove(String var1) {
      synchronized(this) {
         this.checks.remove(var1);
      }
   }

   public void add(String var1, Object var2) {
      synchronized(this) {
         this.checks.put(var1, new Entry(var2));
      }
   }

   public void purge(String var1) {
      synchronized(this) {
         if (elapsed(this.purged, 180000L) && this.checks.size() != 0) {
            int var3 = 0;
            Iterator var4 = this.checks.values().iterator();

            while(var4.hasNext()) {
               Entry var5 = (Entry)var4.next();
               if (var5.isExpired()) {
                  var4.remove();
                  ++var3;
               }
            }

            this.purged = System.currentTimeMillis();
            if (var3 > 0) {
               CommonUtils.print_stat("Purged '" + var1 + "' cache of " + var3 + " entries. Size: " + this.checks.size());
            }

         }
      }
   }

   private static class Entry {
      public Object value;
      public long last;

      public Entry(Object var1) {
         this.value = var1;
         this.touch();
      }

      public void touch() {
         this.last = System.currentTimeMillis();
      }

      public boolean isExpired() {
         return GeneralCache.elapsed(this.last, 480000L);
      }

      public Object get() {
         this.touch();
         return this.value;
      }
   }
}
