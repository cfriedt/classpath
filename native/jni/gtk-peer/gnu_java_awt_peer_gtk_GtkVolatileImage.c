/* gnu_java_awt_peer_gtk_VolatileImage.c
   Copyright (C)  2006 Free Software Foundation, Inc.

This file is part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301 USA.

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version. */

#include "jcl.h"
#include "gtkpeer.h"

#include <gdk/gdk.h>

#include <gdk/gdkx.h>

#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gdk-pixbuf/gdk-pixdata.h>

#include "gnu_java_awt_peer_gtk_GtkVolatileImage.h"
#include "cairographics2d.h"


/**
 * Creates a cairo surface, ARGB32, native ordering, premultiplied alpha.
 */
JNIEXPORT jlong JNICALL 
Java_gnu_java_awt_peer_gtk_GtkVolatileImage_init (JNIEnv *env, 
						  jobject obj __attribute__ ((__unused__)), 
						  jobject peer,
						  jint width, jint height)
{
  
  GtkWidget *widget = NULL;
   #if GTK_MAJOR_VERSION == 2
  GdkPixmap* pixmap;
  #elif GTK_MAJOR_VERSION == 3
  cairo_surface_t *surface;
  #endif
  void *ptr = NULL;
  
  gdk_threads_enter();
 

  if( peer != NULL )
    {
      ptr = gtkpeer_get_widget (env, peer);
      g_assert (ptr != NULL);
      
      widget = GTK_WIDGET (ptr);
      g_assert (widget != NULL);
      
      #if GTK_MAJOR_VERSION == 2
      pixmap = gdk_pixmap_new( gtk_widget_get_window(widget), width, height, -1 );
      #elif GTK_MAJOR_VERSION == 3
      surface = gdk_window_create_similar_surface(gtk_widget_get_window(widget), CAIRO_CONTENT_COLOR_ALPHA, width, height);
      #endif 
   }
  else{
  #if GTK_MAJOR_VERSION == 2
   pixmap = gdk_pixmap_new( NULL, width, height, 
			    gdk_visual_get_depth(gdk_visual_get_system()));
  #elif GTK_MAJOR_VERSION == 3
  surface = gdk_window_create_similar_surface(gtk_widget_get_window(widget), CAIRO_CONTENT_COLOR_ALPHA, width, height);
  #endif
  }
  gdk_threads_leave();

  #if GTK_MAJOR_VERSION == 2
  g_assert( pixmap != NULL );
  return PTR_TO_JLONG(pixmap);
  #elif GTK_MAJOR_VERSION == 3
  g_assert( surface != NULL);
  return PTR_TO_JLONG( surface );
  #endif
}

/**
 * Destroy the surface
 */
#if GTK_MAJOR_VERSION == 3
JNIEXPORT void JNICALL 
Java_gnu_java_awt_peer_gtk_GtkVolatileImage_destroy
(JNIEnv *env __attribute__((unused)), jobject obj __attribute__((unused)),
 jlong pointer)
{ 
  gdk_threads_enter();
  cairo_surface_t *surface = JLONG_TO_PTR(cairo_surface_t, pointer);
  if( surface != NULL )
    {
      
      g_object_unref( surface );
      
    }
  gdk_threads_leave();
}
#endif
#if GTK_MAJOR_VERSION == 2
JNIEXPORT void JNICALL 
Java_gnu_java_awt_peer_gtk_GtkVolatileImage_destroy
(JNIEnv *env __attribute__((unused)), jobject obj __attribute__((unused)),
 jlong pointer)
{
  GdkPixmap* pixmap = JLONG_TO_PTR(GdkPixmap, pointer);
 
  
  if( pixmap != NULL )
    {
       gdk_threads_enter();
      g_object_unref( pixmap);
       gdk_threads_leave();
      
    }
 
}
#endif

/**
 * Gets all pixels in an array
 */
JNIEXPORT jintArray JNICALL 
Java_gnu_java_awt_peer_gtk_GtkVolatileImage_nativeGetPixels
(JNIEnv *env, jobject obj, jlong pointer)
{
 jint *jpixdata;
  #if GTK_MAJOR_VERSION == 2
  GdkPixmap *pixmap;
  
  #endif
  
  GdkPixbuf *pixbuf;
  jintArray jpixels;
  int width, height, size;
  jclass cls;
  jfieldID field;
  guchar *pixels;

  cls = (*env)->GetObjectClass (env, obj);
  field = (*env)->GetFieldID (env, cls, "width", "I");
  g_assert (field != 0);
  width = (*env)->GetIntField (env, obj, field);

  field = (*env)->GetFieldID (env, cls, "height", "I");
  g_assert (field != 0);
  height = (*env)->GetIntField (env, obj, field);

  #if GTK_MAJOR_VERSION == 2
  pixmap = JLONG_TO_PTR(GdkPixmap, pointer);
  g_assert(pixmap != NULL);
  #endif 
 
  

  gdk_threads_enter();
  #if GTK_MAJOR_VERSION == 3
  cairo_surface_t *surface;
  surface = JLONG_TO_PTR(cairo_surface_t, pointer);
  g_assert(surface != NULL);
  #endif
  size = width * height;
  jpixels = (*env)->NewIntArray ( env, size );
  jpixdata = (*env)->GetIntArrayElements (env, jpixels, NULL);
  
  #if GTK_MAJOR_VERSION == 2
  pixbuf = gdk_pixbuf_new( GDK_COLORSPACE_RGB, TRUE, 8, width, height );
  gdk_pixbuf_get_from_drawable( pixbuf, pixmap, NULL, 0, 0, 0, 0, width, height );
  #elif GTK_MAJOR_VERSION == 3
  pixbuf =  gdk_pixbuf_get_from_surface (surface, 0,0,width,height);
  #endif  

  if (pixbuf != NULL)
    {
      pixels = gdk_pixbuf_get_pixels(pixbuf);
      memcpy (jpixdata, pixels, size * sizeof(jint));
    }
    
  (*env)->ReleaseIntArrayElements (env, jpixels, jpixdata, 0);

  gdk_threads_leave();

  return jpixels;
}

/**
 * Copy area
 */
JNIEXPORT void JNICALL 
Java_gnu_java_awt_peer_gtk_GtkVolatileImage_nativeCopyArea
(JNIEnv *env __attribute__((unused)), jobject obj __attribute__((unused)),
 jlong pointer, jint x, jint y, jint w, jint h, jint dx, jint dy)
{ 
  
  GdkPixbuf *pixbuf;
  
  #if GTK_MAJOR_VERSION == 2
  GdkPixmap* pixmap = JLONG_TO_PTR(GdkPixmap, pointer);
  g_assert (pixmap != NULL);
  #elif GTK_MAJOR_VERSION == 3
  cairo_surface_t *surface = JLONG_TO_PTR(cairo_surface_t, pointer);
  g_assert (surface != NULL);
  #endif

  gdk_threads_enter();
  
  #if GTK_MAJOR_VERSION == 2
  pixbuf = gdk_pixbuf_new( GDK_COLORSPACE_RGB, TRUE, 8, w, h );
  gdk_pixbuf_get_from_drawable( pixbuf, pixmap, NULL, x, y, 0, 0, w, h );
  #elif GTK_MAJOR_VERSION == 3
  pixbuf = gdk_pixbuf_get_from_surface (surface, x,y,w,h);
  #endif

  #if GTK_MAJOR_VERSION == 2
  cairo_t *cr = gdk_cairo_create(pixmap);
  #elif GTK_MAJOR_VERSION == 3
  cairo_t *cr = cairo_create (surface);
  #endif

  gdk_cairo_set_source_pixbuf (cr, pixbuf, x + dx, y + dy);
  cairo_paint (cr);
  cairo_destroy (cr);

  gdk_threads_leave();
}

JNIEXPORT void JNICALL 
Java_gnu_java_awt_peer_gtk_GtkVolatileImage_nativeDrawVolatile
(JNIEnv *env __attribute__((unused)), jobject obj __attribute__((unused)),
 jlong pointer, jlong srcptr, jint x, jint y, jint w, jint h)
{
 
  GdkRectangle clip;
  

  gdk_threads_enter();
  cairo_surface_t *dst, *src;
  src = JLONG_TO_PTR(cairo_surface_t, srcptr);
  dst = JLONG_TO_PTR(cairo_surface_t, pointer);
  g_assert (src != NULL);
  g_assert (dst != NULL);
    
  clip.x = 0;
  clip.y = 0;
  clip.width = w;
  clip.height = h;
 
  cairo_t *cr = cairo_create (dst);
  /* clipping restricts the intermediate surface's size, so it's a good idea
  * to use it. */
  gdk_cairo_rectangle (cr, &clip);
  cairo_clip (cr);
  /* Now push a group to change the target */
  cairo_push_group (cr);
  cairo_set_source_surface (cr, src, x, y);
  cairo_paint (cr);
  /* Now copy the intermediate target back */
  cairo_pop_group_to_source (cr);
  cairo_paint (cr);
  cairo_destroy (cr);

  gdk_threads_leave();
}
