#include "pcapreader.h"
#include <pcap.h>
#include <string>
#include <netinet/in.h>
#include <chrono>
#include <functional>
#include <unistd.h>
#include <thread>
#include <iostream>


#define MSINS 1000000
#define BITTOMB 1048576



using namespace std::chrono;

namespace sim {

bool PcapReader::processDump(std::string _file, RandPool* _rand_pool)
{
    try {

        size_t sleep_time = MSINS;
        sleep_time = MSINS/( (((double)m_rate*BITTOMB)/8) / (double)MTU );

        pdump = pcap_dump_open(pcap, _file.c_str());
        if (!pdump) {
            std::cout << "error pcap outfile open" << std::endl;
            return false;
        }
        std::function< void (struct pcap_pkthdr* , const u_char *) > func_obj = [=](struct pcap_pkthdr* header, const u_char* data)
                                                                                   { return pcap_dump((u_char*)pdump, header, data); };

        auto execstart = high_resolution_clock::now();

        uint64_t write_bytes = 0;

        while (!_rand_pool->empty() || !m_terminate) {
            auto iterstart = high_resolution_clock::now();

            uint64_t curr_write_bytes = _rand_pool->processBySize(MTU, func_obj);

            write_bytes += curr_write_bytes;
            auto iterstop = high_resolution_clock::now();
            auto iterduration = duration_cast<microseconds>( iterstop - iterstart);

            if ( (double)sleep_time*((double)curr_write_bytes/MTU) > (double)iterduration.count() ) {
                auto current_time = high_resolution_clock::now();
                auto current_duration = duration_cast<microseconds>( current_time - execstart );
                if ( ( ((double)write_bytes*8 / current_duration.count())*MSINS)/(BITTOMB) > m_rate) {
                    usleep((size_t)((double)sleep_time*((double)curr_write_bytes/MTU) - (double)iterduration.count()));
                }
            }
        }
        auto execstop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>( execstop - execstart);
        std::cout << "write bytes: " << write_bytes <<" time ms : " << duration.count() << std::endl;

        if ( duration.count() ) {
            std::cout << "write Mbps: "<< ((double)( ( (double)(write_bytes * 8) / duration.count()) )*MSINS)/(BITTOMB) << std::endl;
        }

    }
    catch (std::exception& exp) {
        std::cout << exp.what() << std::endl;
        return false;
    }
    return true;
}

bool PcapReader::processFile(const std::string &_file, const std::string &_path, RandPool& _rand_pool, float rate)
{
    try {

        if (rate < std::numeric_limits<float>::epsilon()) {
            std::cout << "~0 Mbps" << std::endl;
            return false;
        }

        m_rate = rate;

        //std::chrono::time_point<std::chrono::system_clock> start, end;
        //start = std::chrono::system_clock::now();

        char errbuff[PCAP_ERRBUF_SIZE];
        pcap = pcap_open_offline(_file.c_str(), errbuff);

        if (!pcap) {
            std::cout << "wrong pcap file" << std::endl;
            return false;
        }
        //int link_type  = pcap_datalink( pcap );

        //std::cout << "link type:" << link_type << std::endl;

        struct pcap_pkthdr *header;
        const u_char *data;
        struct bpf_program fp;

        std::string current_dumper = _path;

        u_int packetCount = 1;
        uint64_t bytesRead = 0;

        std::thread dumper(&sim::PcapReader::processDump, this, _path, &_rand_pool);

        auto execstart = high_resolution_clock::now();

        while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
        {

            static const ushort eth802 = ntohs(0x8100);
            static const ushort ethip4 = ntohs(0x0800);
            static const ushort ethip6 = ntohs(0x86DD);

            _rand_pool.addPacket(header, data);

            bytesRead += header->caplen;
            packetCount+=1;

        }
        m_terminate = true;

        auto execstop = high_resolution_clock::now();

        auto duration = duration_cast<microseconds>( execstop - execstart);

        std::cout << "read bytes: " << bytesRead <<" time ms : " << duration.count() << std::endl;

        if ( duration.count() ) {
            std::cout << "read Mbps: "<< ((double)( ( (double)(bytesRead * 8) / duration.count()) )*1000000)/(1024*1024) << std::endl;
        }


        dumper.join();

        if ( pdump ) {
            pcap_dump_close(pdump);
            pcap_close(pcap);
        }


    }
    catch(std::exception& exp) {
        std::cout << exp.what() << std::endl;
        return false;
    }

    return true;

}

}
