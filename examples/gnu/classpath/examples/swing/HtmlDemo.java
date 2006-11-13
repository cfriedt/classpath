/* HtmlDemo.java -- HTML viewer demo
   Copyright (C) 2006 Free Software Foundation, Inc.

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


package gnu.classpath.examples.swing;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.URL;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;

/**
 * Parses and displays HTML content.
 * 
 * @author Audrius Meskauskas (audriusa@bioinformatics.org)
 */
public class HtmlDemo extends JPanel
{ 

  private class LoadActionListener
    implements ActionListener
  {

    public void actionPerformed(ActionEvent event)
    {
      String urlStr = url.getText();
      try
        {
          html.setPage(url.getText());
        }
      catch (IOException ex)
        {
          System.err.println("exception while loading: " + ex);
          ex.printStackTrace();
        }
    }
  }

  /**
   * Setting this to true causes the parsed element structure to be dumped.
   */
  private static final boolean DEBUG = true;

  /**
   * The URL entry field.
   */
  JTextField url = new JTextField(); 

  JTextPane html = new JTextPane();
  
  int n;

  public HtmlDemo()
  {
    super();
    html.setContentType("text/html"); // not now.
    createContent();
  }

  /**
   * Returns a panel with the demo content. The panel uses a BorderLayout(), and
   * the BorderLayout.SOUTH area is empty, to allow callers to add controls to
   * the bottom of the panel if they want to (a close button is added if this
   * demo is being run as a standalone demo).
   */
  private void createContent()
  {
    setLayout(new BorderLayout());

    html.setEditable(false);
    html.addHyperlinkListener(new HyperlinkListener()
    {

      public void hyperlinkUpdate(HyperlinkEvent event)
      {
        URL u = event.getURL();
        if (u != null)
          {
            url.setText(u.toString());
            try
              {
                html.setPage(u);
              }
            catch (IOException ex)
              {
                ex.printStackTrace();
              }
          }
      }
      
    });

    JScrollPane scroller = new JScrollPane(html);
    JPanel urlPanel = new JPanel();
    urlPanel.setLayout(new BoxLayout(urlPanel, BoxLayout.X_AXIS));
    url.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
    LoadActionListener action = new LoadActionListener();
    url.addActionListener(action);
    urlPanel.add(url);
    JButton loadButton = new JButton("go");
    urlPanel.add(loadButton);
    loadButton.addActionListener(action);
    add(urlPanel, BorderLayout.NORTH);
    add(scroller, BorderLayout.CENTER);

    // Load start page.
    URL startpage = getClass().getResource("welcome.html");
    try
      {
        html.setPage(startpage);
        url.setText(startpage.toString());
      }
    catch (IOException ex)
      {
        System.err.println("couldn't load page: " + startpage);
      }

    setPreferredSize(new Dimension(600, 400));
  }
 
  /**
   * The executable method to display the editable table.
   * 
   * @param args
   *          unused.
   */
  public static void main(String[] args)
  {
    SwingUtilities.invokeLater
    (new Runnable()
     {
       public void run()
       {
         HtmlDemo demo = new HtmlDemo();
         JFrame frame = new JFrame();
         frame.getContentPane().add(demo);
         frame.setSize(new Dimension(700, 480));
         frame.setVisible(true);
       }
     });
  }

  /**
   * Returns a DemoFactory that creates a HtmlDemo.
   *
   * @return a DemoFactory that creates a HtmlDemo
   */
  public static DemoFactory createDemoFactory()
  {
    return new DemoFactory()
    {
      public JComponent createDemo()
      {
        return new HtmlDemo();
      }
    };
  }
}

