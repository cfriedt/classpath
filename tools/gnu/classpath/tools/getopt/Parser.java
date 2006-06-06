/* Parser.java - parse command line options
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


package gnu.classpath.tools.getopt;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * An instance of this class is used to parse command-line options. It does "GNU
 * style" argument recognition and also automatically handles "--help" and
 * "--version" processing. It can also be put in "long option only" mode. In
 * this mode long options are recognized with a single dash (as well as a double
 * dash) and strings of options like "-abc" are never parsed as a collection of
 * short options.
 */
public class Parser
{
  private String programName;

  private String headerText;

  private String footerText;

  private boolean longOnly;

  private ArrayList options = new ArrayList();

  private ArrayList optionGroups = new ArrayList();

  private OptionGroup defaultGroup = new OptionGroup();

  // These are used while parsing.
  private int currentIndex;

  private String[] args;

  /**
   * Create a new parser. The program name is used when printing error messages.
   * The version string is printed verbatim in response to "--version".
   * 
   * @param programName the name of the program
   * @param versionString the program's version information
   */
  public Parser(String programName, String versionString)
  {
    this(programName, versionString, false);
  }

  /**
   * Create a new parser. The program name is used when printing error messages.
   * The version string is printed verbatim in response to "--version".
   * 
   * @param programName the name of the program
   * @param versionString the program's version information
   * @param longOnly true if the parser should work in long-option-only mode
   */
  public Parser(String programName, final String versionString, boolean longOnly)
  {
    this.programName = programName;
    this.longOnly = longOnly;
    defaultGroup.add(new Option("help", "print this help, then exit")
    {
      public void parsed(String argument) throws OptionException
      {
        printHelp(System.out);
        System.exit(0);
      }
    });
    defaultGroup.add(new Option("version", "print version number, then exit")
    {
      public void parsed(String argument) throws OptionException
      {
        System.out.println(versionString);
        System.exit(0);
      }
    });
    add(defaultGroup);
  }

  /**
   * Set the header text that is printed by --help.
   * 
   * @param headerText the header text
   */
  public void setHeader(String headerText)
  {
    this.headerText = headerText;
  }

  /**
   * Set the footer text that is printed by --help.
   * 
   * @param footerText the footer text
   */
  public void setFooter(String footerText)
  {
    this.footerText = footerText;
  }

  /**
   * Add an option to this parser. The option is added to the default option
   * group; this affects where it is placed in the help output.
   * 
   * @param opt the option
   */
  public synchronized void add(Option opt)
  {
    options.add(opt);
    defaultGroup.add(opt);
  }

  /**
   * Add an option group to this parser. All the options in this group will be
   * recognized by the parser.
   * 
   * @param group the option group
   */
  public synchronized void add(OptionGroup group)
  {
    options.addAll(group.options);
    optionGroups.add(group);
  }

  void printHelp(PrintStream out)
  {
    if (headerText != null)
      {
        out.println(headerText);
        out.println();
      }

    Iterator it = optionGroups.iterator();
    while (it.hasNext())
      {
        OptionGroup group = (OptionGroup) it.next();
        group.printHelp(out);
        out.println();
      }

    if (footerText != null)
      out.println(footerText);
  }

  private String getArgument(String request) throws OptionException
  {
    ++currentIndex;
    if (currentIndex >= args.length)
      throw new OptionException("option '" + request + "' requires an argument");
    return args[currentIndex];
  }

  private void handleLongOption(String real, int index) throws OptionException
  {
    String option = real.substring(index);
    String justName = option;
    int eq = option.indexOf('=');
    if (eq != - 1)
      justName = option.substring(0, eq);
    Option found = null;
    for (int i = options.size() - 1; i >= 0; --i)
      {
        Option opt = (Option) options.get(i);
        if (justName.equals(opt.getLongName()))
          {
            found = opt;
            break;
          }
      }
    if (found == null)
      throw new OptionException("unrecognized option '" + real + "'");
    String argument = null;
    if (found.getTakesArgument())
      {
        if (eq == - 1)
          argument = getArgument(real);
        else
          argument = option.substring(eq + 1);
      }
    else if (eq != - 1)
      {
        throw new OptionException("option '" + real.substring(0, eq + index)
                                  + "' doesn't allow an argument");
      }
    found.parsed(argument);
  }

  private void handleShortOption(char option) throws OptionException
  {
    Option found = null;
    for (int i = options.size() - 1; i >= 0; --i)
      {
        Option opt = (Option) options.get(i);
        if (option == opt.getShortName())
          {
            found = opt;
            break;
          }
      }
    if (found == null)
      throw new OptionException("unrecognized option '-" + option + "'");
    String argument = null;
    if (found.getTakesArgument())
      argument = getArgument("-" + option);
    found.parsed(argument);
  }

  private void handleShortOptions(String option) throws OptionException
  {
    for (int i = 1; i < option.length(); ++i)
      {
        handleShortOption(option.charAt(i));
      }
  }

  /**
   * Parse a command line. Any files which are found will be passed to the file
   * argument callback. This method will exit on error or when --help or
   * --version is specified.
   * 
   * @param inArgs the command-line arguments
   * @param files the file argument callback
   */
  public synchronized void parse(String[] inArgs, FileArgumentCallback files)
  {
    try
      {
        args = inArgs;
        for (currentIndex = 0; currentIndex < args.length; ++currentIndex)
          {
            if (args[currentIndex].length() == 0
                || args[currentIndex].charAt(0) != '-'
                || "-".equals(args[currentIndex]))
              {
                files.notifyFile(args[currentIndex]);
                continue;
              }
            if ("--".equals(args[currentIndex]))
              break;
            if (args[currentIndex].charAt(1) == '-')
              handleLongOption(args[currentIndex], 2);
            else if (longOnly)
              handleLongOption(args[currentIndex], 1);
            else
              handleShortOptions(args[currentIndex]);
          }
        // Add remaining arguments to leftovers.
        for (++currentIndex; currentIndex < args.length; ++currentIndex)
          files.notifyFile(args[currentIndex]);
      }
    catch (OptionException err)
      {
        System.err.println(programName + ": " + err.getMessage());
        System.err.println(programName + ": Try '" + programName
                           + " --help' for more information.");
        System.exit(1);
      }
  }

  /**
   * Parse a command line. Any files which are found will be returned. This
   * method will exit on error or when --help or --version is specified.
   * 
   * @param inArgs the command-line arguments
   */
  public String[] parse(String[] inArgs)
  {
    final ArrayList fileResult = new ArrayList();
    parse(inArgs, new FileArgumentCallback()
    {
      public void notifyFile(String fileArgument)
      {
        fileResult.add(fileArgument);
      }
    });
    return (String[]) fileResult.toArray(new String[0]);
  }
}
