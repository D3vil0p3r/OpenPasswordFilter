// This file is part of OpenPasswordFilter.
// 
// OpenPasswordFilter is free software; you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// OpenPasswordFilter is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with OpenPasswordFilter; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111 - 1307  USA
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.DirectoryServices.AccountManagement;
using System.Security.Cryptography;

namespace OPFService
{
    class OPFDictionary
    {
        HashSet<string> matchlist;
        List<string> contlist;
        List<Regex> regexlist;
        List<Regex> noregexlist;
        string pathmatch;
        string pathcont;
        string pathregex;
        string pathnoregex;

        DateTime matchmtime;
        DateTime contmtime;
        DateTime regexmtime;
        DateTime noregexmtime;

        public void writeLog(string message, System.Diagnostics.EventLogEntryType level)
        {
            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "OpenPasswordFilter";
                eventLog.WriteEntry(message, level, 103, 1);
            }
        }
        public void writeLogWarning(string message, System.Diagnostics.EventLogEntryType level)
        {
            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "OpenPasswordFilter";
                eventLog.WriteEntry(message, level, 104, 1);
            }
        }
        public void writeLogWarningSecurity(string message, System.Diagnostics.EventLogEntryType level)
        {
            using (EventLog eventLog = new EventLog("Security"))
            {
                eventLog.Source = "OpenPasswordFilter";
                eventLog.WriteEntry(message, level, 104, 1);
            }
        }

        public void writeLogError(string message, System.Diagnostics.EventLogEntryType level)
        {
            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "OpenPasswordFilter";
                eventLog.WriteEntry(message, level, 105, 1);
            }
        }
        public OPFDictionary(string m, string c, string r, string n)
        {

            pathmatch = m;
            pathcont = c;
            pathregex = r;
            pathnoregex = n;

            writeLog("Opening Match Configuration File " + pathmatch, EventLogEntryType.Information);
            ReadInMatchFile();
            writeLog("Opening Contains Configuration File " + pathcont, EventLogEntryType.Information);
            ReadInContFile();
            writeLog("Opening Regular Expression Configuration File " + pathregex, EventLogEntryType.Information);
            ReadInRegexFile();
            writeLog("Opening No Regular Expression Configuration File " + pathnoregex, EventLogEntryType.Information);
            ReadInNoRegexFile();

            writeLog("Successfully parsed all configuration files", EventLogEntryType.Information);

        }

        private void ReadInRegexFile()
        {
            string line;
            regexmtime = File.GetLastWriteTimeUtc(pathregex);
            StreamReader infileregex = new StreamReader(pathregex);
            regexlist = new List<Regex>();
            int a = 1;
            while ((line = infileregex.ReadLine()) != null)
            {
                try
                {
                    regexlist.Add(new Regex(line));
                    a += 1;
                }
                catch
                {
                    writeLogError("Died trying to ingest line number " + a.ToString() + " of opfregex.txt.", EventLogEntryType.Error);
                }
            }
            infileregex.Close();
        }

        private void ReadInNoRegexFile()
        {
            string line;
            noregexmtime = File.GetLastWriteTimeUtc(pathnoregex);
            StreamReader infilenoregex = new StreamReader(pathnoregex);
            noregexlist = new List<Regex>();
            int a = 1;
            while ((line = infilenoregex.ReadLine()) != null)
            {
                try
                {
                    noregexlist.Add(new Regex(line));
                    a += 1;
                }
                catch
                {
                    writeLogError("Died trying to ingest line number " + a.ToString() + " of opfnoregex.txt.", EventLogEntryType.Error);
                }
            }
            infilenoregex.Close();
        }

        private void ReadInContFile()
        {
            string line;
            contmtime = File.GetLastWriteTimeUtc(pathcont);
            StreamReader infilecont = new StreamReader(pathcont);
            contlist = new List<string>();
            int a = 1;
            while ((line = infilecont.ReadLine()) != null)
            {
                try
                {
                    contlist.Add(line.ToLower());
                    a += 1;
                }
                catch
                {
                    writeLogError("Died trying to ingest line number " + a.ToString() + " of opfcont.txt.", EventLogEntryType.Error);
                }
            }
            infilecont.Close();
        }

        private void ReadInMatchFile()
        {
            string line;
            matchmtime = File.GetLastWriteTimeUtc(pathmatch);
            StreamReader infilematch = new StreamReader(pathmatch);
            matchlist = new HashSet<string>();
            int a = 1;
            while ((line = infilematch.ReadLine()) != null)
            {
                try
                {
                    matchlist.Add(line.ToLower());
                    a += 1;
                }
                catch
                {
                    writeLogError("Died trying to ingest line number " + a.ToString() + " of opfmatch.txt", EventLogEntryType.Error);
                }
            }
            infilematch.Close();
        }

        private void CheckFileFreshness()
        {
            if (matchmtime != File.GetLastWriteTimeUtc(pathmatch))
            {
                writeLog("OPFMatch.txt has changed. Rereading now...", EventLogEntryType.Information);
                ReadInMatchFile();
            }
            if (contmtime != File.GetLastWriteTimeUtc(pathcont))
            {
                writeLog("OPFCont.txt has changed. Rereading now...", EventLogEntryType.Information);
                ReadInContFile();
            }
            if (regexmtime != File.GetLastWriteTimeUtc(pathregex))
            {
                writeLog("OPFRegex.txt has changed. Rereading now...", EventLogEntryType.Information);
                ReadInRegexFile();
            }
            if (noregexmtime != File.GetLastWriteTimeUtc(pathnoregex))
            {
                writeLog("OPFnoRegex.txt has changed. Rereading now...", EventLogEntryType.Information);
                ReadInNoRegexFile();
            }
        }

        public Boolean contains(string word, string username)
        {
            CheckFileFreshness();
            foreach (string badstr in contlist)
            {
                if (word.ToLower().Contains(badstr))
                {
                    writeLogWarning("Password attempt contains poison string.", EventLogEntryType.Warning);
                    writeLogWarningSecurity("Password attempt contains poison string " + badstr + ", case insensitive.", EventLogEntryType.Warning);
                    return true;
                }
            }

            if (matchlist.Contains(word.ToLower()))
            {
                writeLogWarning("Password attempt matched a string in the bad password list", EventLogEntryType.Warning);
                return true;
            }

            foreach (Regex r in regexlist)
            {
                Match m = r.Match(word);
                writeLog("Password evaluated by regular expression " + r.ToString(), EventLogEntryType.Information);
                if (m.Success)
                {
                    writeLogWarning("Password attempt matched regular expression " + r.ToString(), EventLogEntryType.Warning);
                    return true;
                }
            }

            foreach (Regex n in noregexlist)
            {
                Match nm = n.Match(word);

                writeLog("Password evaluated by regular expression " + n.ToString(), EventLogEntryType.Information);
                if (nm.Success)
                {
                    writeLog("Password attempt matched no regular expression " + n.ToString(), EventLogEntryType.Information);
                }
                else
                {
                    writeLogWarning("Password attempt not matched no regular expression " + n.ToString(), EventLogEntryType.Warning);
                    return true;
                }
            }
            Dictionary<string, string> namedict = new Dictionary<string, string>();
            using (PrincipalContext context = new PrincipalContext(ContextType.Domain))
            {
                using (UserPrincipal user = UserPrincipal.FindByIdentity(context, username))
                {
                    if (user != null)
                    {
                        namedict.Add("full name", user.DisplayName);
                        namedict.Add("given name", user.GivenName);
                        namedict.Add("surname", user.Surname);
                        namedict.Add("SAMAccountName", user.SamAccountName);
                    }
                }
            }
            foreach (string key in namedict.Keys)
            {
                if (namedict[key] != null)
                {
                    if (word.ToLower().Contains(namedict[key].ToLower()))
                    {
                        writeLogWarning("Password attempt contained the user's " + key + ",", EventLogEntryType.Warning);
                        return true;
                    }
                }
            }
            writeLog("Password passed custom filter.", EventLogEntryType.Information);
            return false;
        }
    }
}