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

                    ReadFromFile(ref reader);
                    
                }
                    // TODO fix this bug with reading after file ending
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            else throw new FileNotFoundException();
        }

        private void ReadFromFile(ref System.IO.BinaryReader reader)
        {
            while (reader.ReadByte() > 0)
            {
                // Variables for TCPandUDPFrame filling
                uint frameLength = ReadLeghtFrame(ref reader);

                var ethernetDestinationIp = ReadDestinationEthernetIP(ref reader);

                var ethernetSourceIp = ReadSourceEthernetIp(ref reader);

                // Missed
                reader.ReadBytes(11);

                // Read Protocol Identificator
                uint protocolNumber = reader.ReadByte();

                // Missed
                reader.ReadByte();
                reader.ReadByte();

                // Fill Source & Destination IP
                var sourceIp = ReadSourceIp(ref reader);
                var destinationIp = ReadDestinationIp(ref reader);

                // ReadUInt16 reads in another endian, so we have to use this trick ( multiply 256 is the same for 8 bit offset to the left)
                var draftPort = ReadDraftPort(ref reader);

                var sourcePort = draftPort[0] * 256 + draftPort[1];

                var destinationPort = ReadDestPort(draftPort, ref reader);
                
                var ethernetFrame = new EthernetFrame(ethernetDestinationIp, ethernetSourceIp);

                // Fill current TCPandUDPFrame
                var T = new TCPandUDPFrame(destinationIp, destinationPort, frameLength, sourceIp, sourcePort,
                    protocolNumber);
                
                // Pull current TCPandUDPFrame to dump
                TCPFrameArray.Add(T);

                // Pull current Ethernet frame to dump
                EthernetFrameArray.Add(ethernetFrame);

                // Miss ending of pcap-file, witch depends on FrameLength
                reader.ReadBytes((int)(frameLength - 38));
            }
        }

        private uint ReadDestPort(uint[] DraftPort, ref System.IO.BinaryReader reader)
        {
            for (int i = 0; i < 2; ++i)
                DraftPort[i] = reader.ReadByte();

            return DraftPort[0] * 256 + DraftPort[1];
        }

        private uint[] ReadDraftPort( ref System.IO.BinaryReader reader)
        {
            var draftPort = new uint[2];

            for (int i = 0; i < 2; ++i)
                draftPort[i] = reader.ReadByte();

            return draftPort;
        }

        private int[] ReadSourceEthernetIp(ref System.IO.BinaryReader reader)
        {
            var ethernetSourceIp = new int[6];

            for (int i = 0; i < 6; ++i)
                ethernetSourceIp[i] = reader.ReadByte();

            return ethernetSourceIp;
        }

        private int[] ReadDestinationEthernetIP( ref System.IO.BinaryReader reader)
        {
            var ethernetDestinationIp = new int[6];

            // Get Ethernet info
            for (int i = 0; i < 6; ++i)
                ethernetDestinationIp[i] = reader.ReadByte();
 
            return ethernetDestinationIp;
        }
        
        private uint ReadLeghtFrame(ref System.IO.BinaryReader reader)
        {
            // Missed frame header
            reader.ReadBytes(7);

            // Read amount of bytes in this frame
            var FrameLength = reader.ReadUInt32();

            reader.ReadBytes(4); 
            return FrameLength;
        }

        private int[] ReadSourceIp(ref System.IO.BinaryReader reader)
        {
            var SourceIP = new int[4];

            for (int i = 0; i < 4; ++i)
                SourceIP[i] = reader.ReadByte();

            return SourceIP;
        }

        private int[] ReadDestinationIp(ref System.IO.BinaryReader reader)
        {
            var DestinationIP = new int[4];

            for (int j = 0; j < 4; ++j)
                DestinationIP[j] = reader.ReadByte();

            return DestinationIP;
        }
        
        // Get this dump of processed frames
        public ArrayList GetTcpFrameList()
        {
            return TCPFrameArray;
        }

        public ArrayList GetEthernetFrameList()
        {
            return EthernetFrameArray;
        }
    }
}