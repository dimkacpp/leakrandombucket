#include <boost/program_options.hpp>
#include <iostream>
#include "pcapreader.h"
#include "randpool.h"

namespace opt = boost::program_options;

int main(int argc, char** argv)
{

    opt::options_description desc("oxyinstaller options");
    opt::variables_map vm;

    try {

        desc.add_options()
            ("input,i", opt::value<std::string>()->required(), "input pcap file")
            ("output,o", opt::value<std::string>()->required(), "output pcap file")
            ("rate,r", opt::value<float>()->required(), "Mbps")
            ("help,h", "produce help message");

        opt::store(opt::parse_command_line(argc, argv, desc), vm);



        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return 0;
        }

        opt::notify(vm);

        sim::RandPool randpool;
        sim::PcapReader pcap_reader;

        pcap_reader.processFile(vm["input"].as<std::string>(), vm["output"].as<std::string>(), randpool, vm["rate"].as<float>());

    }
    catch (opt::required_option& ex) {
        std::cout << " Required option!\n" << ex.what() << "\nuse:\n" << desc << std::endl;
        return 1;
    }
    catch (std::exception& stdex) {
        std::cout << stdex.what()  << std::endl;

    }
    catch (...) {
        std::cout << "something went wrong (((" << std::endl;
    }

    return 0;
}
