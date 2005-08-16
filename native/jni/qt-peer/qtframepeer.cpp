/* qtframepeer.cpp --
   Copyright (C)  2005  Free Software Foundation, Inc.

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

#include <QApplication>
#include <QMainWindow>
#include <QMenuBar>
#include <QToolBar>
#include <QThread>
#include <gnu_java_awt_peer_qt_QtFramePeer.h>
#include "qtcomponent.h"
#include "qtstrings.h"
#include "containers.h"
#include "keybindings.h"
#include "mainthreadinterface.h"

#define MenuSizeDefault 5

/*
 * Our QMainWindow subclass
 */
class MyWindow : public QMainWindow
{
public:
  MyWindow(JNIEnv *env, jobject obj) : QMainWindow(0, Qt::Window )
  {
    setup(env, obj);
  }

  ~MyWindow()
  {
    destroy();
  }

#define I_KNOW_WHAT_IM_DOING
#define PARENT QMainWindow
#include "eventmethods.cpp"
};

/**
 * Event wrapper for adding a menu bar to the frame
 * if the QMenuBar pointer is NULL, the current menu bar is removed.
 */
class FrameMenuEvent : public AWTEvent {
  
 private:
  QMainWindow *widget;
  QMenuBar *menu;
  
 public:
  FrameMenuEvent(QMainWindow *w, QMenuBar *mb) : AWTEvent()
  {
    widget = w;
    menu = mb;
  }

  void runEvent()
  {
    if( menu != NULL)
      widget->setMenuBar( menu );
    else
      delete widget->menuBar();
  }
};

/**
 * Event wrapper for getting the menu bar height
 */
class FrameGetMenuHeightEvent : public AWTEvent {
  
private:
  QMainWindow *frame;
  int *value;
  
public:
  FrameGetMenuHeightEvent(QMainWindow *w, int *v) : AWTEvent()
  {
    frame = w;
    value = v;
  }

  void runEvent()
  {
    QMenuBar *mb = frame->menuBar();
    assert( mb );
    int v;
    if( mb->isVisible() )
      v = mb->size().height();

    if(v <= 0 || v >= 0xFFFFF )  // Work around for strange values.
      v = MenuSizeDefault; 

    *value = v;
  }
};

/**
 * Returns the child widget for the frame (the centralWidget in qt terms)
 */
QWidget *frameChildWidget( JNIEnv *env, jobject component )
{
  jclass frameCls = env->FindClass( "java/awt/Frame" );
  assert( frameCls );
  jmethodID getPeerMID = env->GetMethodID( frameCls,
					   "getPeer",
					   "()Ljava/awt/peer/ComponentPeer;" );
  assert(getPeerMID);
  jobject framepeerobj = env->CallObjectMethod( component, getPeerMID, 0);

  QMainWindow *window = (QMainWindow *)getNativeObject(env, framepeerobj);

  return window->centralWidget();
}

/*
 * Constructs a QMainWindow native object.
 */
JNIEXPORT void JNICALL Java_gnu_java_awt_peer_qt_QtFramePeer_init
(JNIEnv *env, jobject obj)
{
  MyWindow *frame = new MyWindow(env, obj);
  assert( frame );

  QWidget *central = new QWidget( frame );
  assert( central );

  frame->setCentralWidget( central );
  setNativeObject( env, obj, frame );
}

/**
 * Returns the menu bar height for insets.
 */
JNIEXPORT jint JNICALL Java_gnu_java_awt_peer_qt_QtFramePeer_menuBarHeight
(JNIEnv *env, jobject obj)
{
  QMainWindow *frame = (QMainWindow *) getNativeObject( env, obj );
  assert( frame );

  int value = 0;
  mainThread->postEventToMain( new FrameGetMenuHeightEvent( frame, &value ) );

  while(value == 0); // (Busy) wait for the value to
  // get set by the main thread.

  return (jint)value;
}

/*
 * set Menu bar.
 */
JNIEXPORT void JNICALL Java_gnu_java_awt_peer_qt_QtFramePeer_setMenu
(JNIEnv *env, jobject obj, jobject mbPeer)
{
  QMainWindow *frame = (QMainWindow *) getNativeObject( env, obj );
  assert( frame );
  
  QMenuBar *menubar = NULL;

  if( mbPeer != NULL )
    {
      menubar = (QMenuBar *) getNativeObject( env, mbPeer );
      assert( menubar );
    }

  mainThread->postEventToMain( new FrameMenuEvent( frame, menubar ) );
}


