using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

namespace PcapdotNET.Protocols
{
    // Processing pcap file
    public class FileParser
    {
        // Put here all info, collected from file
        private readonly ArrayList EthernetFrameArray = new ArrayList();
        private readonly ArrayList TCPFrameArray = new ArrayList();

        public FileParser(string _FileName)
        {
            if (File.Exists(_FileName))
            {
                var reader = new BinaryReader(File.Open(_FileName, FileMode.Open));

                try
                {
                    // Missed header of file
                    reader.ReadBytes(24);

                    while (reader.ReadByte() > 0)
                    {
                        // Variables for TCPandUDPFrame filling
                        var DestinationIP = new int[4];

                        uint DestinationPort;

                        uint FrameLength;

                        var SourceIP = new int[4];

                        uint SourcePort;

                        uint ProtocolNumber;

                        var EthernetDestinationIP = new int[6];

                        var EthernetSourceIP = new int[6];


                        // Missed frame header
                        reader.ReadBytes(7);

                        // Read amount of bytes in this frame
                        FrameLength = reader.ReadUInt32();

                        reader.ReadBytes(4);

                        // Get Ethernet info
                        for (int i = 0; i < 6; ++i)
                            EthernetDestinationIP[i] = reader.ReadByte();

                        for (int i = 0; i < 6; ++i)
                            EthernetSourceIP[i] = reader.ReadByte();

                        // Missed
                        reader.ReadBytes(11);

                        // Read Protocol Identificator
                        ProtocolNumber = reader.ReadByte();

                        // Missed
                        reader.ReadByte();
                        reader.ReadByte();

                        // Fill Source & Destination IP
                        ReadSourceIp(SourceIP, ref reader);
                        ReadDestinationIp(DestinationIP, ref reader);
       
                        // ReadUInt16 reads in another endian, so we have to use this trick ( multiply 256 is the same for 8 bit offset to the left)
                        var DraftPort = new uint[2];

                        for (int i = 0; i < 2; ++i)
                            DraftPort[i] = reader.ReadByte();

                        SourcePort = DraftPort[0]*256 + DraftPort[1];


                        for (int i = 0; i < 2; ++i)
                            DraftPort[i] = reader.ReadByte();

                        DestinationPort = DraftPort[0]*256 + DraftPort[1];

                        var ethernetFrame = new EthernetFrame(EthernetDestinationIP, EthernetSourceIP);

                        // Fill current TCPandUDPFrame !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                        var T = new TCPandUDPFrame(DestinationIP, DestinationPort, FrameLength, SourceIP, SourcePort,
                            ProtocolNumber);
                        //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

                        // Pull current TCPandUDPFrame to dump
                        TCPFrameArray.Add(T);

                        // Pull current Ethernet frame to dump
                        EthernetFrameArray.Add(ethernetFrame);

                        // Miss ending of pcap-file, witch depends on FrameLength
                        reader.ReadBytes((int) (FrameLength - 38));
                    }
                }

                    // TODO fix this bug with reading after file ending
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            else throw new FileNotFoundException();
        }

        private void ReadSourceIp(IList<int> SourceIP, ref System.IO.BinaryReader reader)
        {
            for (int i = 0; i < 4; ++i)
                SourceIP[i] = reader.ReadByte();
        }
        private void ReadDestinationIp(IList<int> DestinationIP, ref System.IO.BinaryReader reader)
        {
            for (int j = 0; j < 4; ++j)
                DestinationIP[j] = reader.ReadByte();
        }
        // Get this dump of processed frames
        public ArrayList GetTCPFrameList()
        {
            return TCPFrameArray;
        }

        public ArrayList GetEthernetFrameList()
        {
            return EthernetFrameArray;
        }
    }
}