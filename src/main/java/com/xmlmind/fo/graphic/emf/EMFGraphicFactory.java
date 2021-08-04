package com.xmlmind.fo.graphic.emf;

import com.xmlmind.fo.graphic.Graphic;
import com.xmlmind.fo.graphic.GraphicEnv;
import com.xmlmind.fo.graphic.GraphicFactory;
import com.xmlmind.fo.graphic.GraphicImpl;
import com.xmlmind.fo.graphic.GraphicUtil;
import com.xmlmind.fo.util.URLUtil;
import java.io.File;
import java.io.InputStream;

public final class EMFGraphicFactory implements GraphicFactory {
   private static final String[] formats = new String[]{"image/x-emf", "image/emf"};

   public String[] getInputFormats() {
      return formats;
   }

   public String[] getOutputFormats() {
      return formats;
   }

   public Graphic createGraphic(String var1, String var2, Object var3, GraphicEnv var4) throws Exception {
      var2 = normalizeMIMEType(var2);
      InputStream var11 = URLUtil.openStream(var1);

      int var5;
      int var6;
      double var7;
      double var9;
      try {
         EMFHeader var12 = EMFHeader.read(var11);
         var5 = var12.boundsRight - var12.boundsLeft;
         var6 = var12.boundsBottom - var12.boundsTop;
         var7 = (double)var5 * 2540.0D / (double)(var12.frameRight - var12.frameLeft);
         var9 = (double)var6 * 2540.0D / (double)(var12.frameBottom - var12.frameTop);
      } finally {
         var11.close();
      }

      return new GraphicImpl(var1, var2, var5, var6, var7, var9, 0, var3);
   }

   private static String normalizeMIMEType(String var0) {
      var0 = URLUtil.normalizeMIMEType(var0);
      if ("image/emf".equals(var0)) {
         var0 = "image/x-emf";
      }

      return var0;
   }

   public Graphic convertGraphic(Graphic var1, String var2, double var3, double var5, Object var7, GraphicEnv var8) throws Exception {
      var2 = normalizeMIMEType(var2);
      if (var3 <= 0.0D) {
         var3 = 1.0D;
      }

      if (var5 <= 0.0D) {
         var5 = 1.0D;
      }

      if (var3 == 1.0D && var5 == 1.0D) {
         File var9 = var8.createTempFile(".emf");
         GraphicUtil.saveGraphic(var1, var9);
         return new GraphicImpl(URLUtil.fileToLocation(var9), var2, var1.getWidth(), var1.getHeight(), var1.getXResolution(), var1.getYResolution(), 0, var7);
      } else {
         throw new UnsupportedOperationException("cannot scale (" + var3 + "x" + var5 + ") an EMF graphic");
      }
   }
}
