#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "../../core/dma_interface/dma_interface.hpp"
#include "../../core/memory_dump/dump_manager.hpp"
#include "../../analysis/static_analysis/static_analyzer.hpp"
#include "../../analysis/dynamic_analysis/dynamic_analyzer.hpp"
#include "../../analysis/symbol_resolver/symbol_resolver.hpp"
#include <memory>

namespace py = pybind11;

PYBIND11_MODULE(dma_debugger, m) {
    m.doc() = "DMA Debugger - Remote memory analysis and reverse engineering";

    py::class_<dma::DMAInterface>(m, "DMAInterface")
        .def(py::init<>())
        .def("initialize", &dma::DMAInterface::initialize,
             py::arg("config") = dma::DMAInterface::Config{})
        .def("shutdown", &dma::DMAInterface::shutdown)
        .def("is_initialized", &dma::DMAInterface::is_initialized)
        .def("read", [](dma::DMAInterface& d, uint64_t addr, size_t size) {
            std::vector<uint8_t> buf(size);
            size_t n = d.read(addr, buf.data(), size);
            buf.resize(n);
            return buf;
        })
        .def("dump", [](dma::DMAInterface& d, const std::string& path) {
            return d.dump_memory(path);
        });

    py::class_<dma::DumpManager>(m, "DumpManager")
        .def(py::init<dma::DMAInterface*>())
        .def("create_dump", &dma::DumpManager::create_dump)
        .def("open_dump", &dma::DumpManager::open_dump)
        .def("read", [](dma::DumpManager& dm, uint64_t addr, size_t size) {
            auto opt = dm.read(addr, size);
            return opt ? py::cast(*opt) : py::none();
        })
        .def("close", &dma::DumpManager::close)
        .def("is_open", &dma::DumpManager::is_open);

    py::class_<dma::StaticAnalyzer>(m, "StaticAnalyzer")
        .def(py::init<dma::DMAInterface*, dma::DumpManager*>())
        .def("find_pe_images", &dma::StaticAnalyzer::find_pe_images)
        .def("scan_pattern", &dma::StaticAnalyzer::scan_pattern)
        .def("scan_pattern_ida", &dma::StaticAnalyzer::scan_pattern_ida)
        .def("extract_strings", &dma::StaticAnalyzer::extract_strings,
             py::arg("base"), py::arg("size"), py::arg("min_length") = 4)
        .def("locate_modules", &dma::StaticAnalyzer::locate_modules)
        .def("get_entropy", &dma::StaticAnalyzer::get_entropy);

    py::class_<dma::PEModule>(m, "PEModule")
        .def_readonly("base_address", &dma::PEModule::base_address)
        .def_readonly("size", &dma::PEModule::size)
        .def_readonly("name", &dma::PEModule::name)
        .def_readonly("path", &dma::PEModule::path)
        .def_readonly("is_64bit", &dma::PEModule::is_64bit)
        .def_readonly("is_kernel", &dma::PEModule::is_kernel);

    py::class_<dma::ProcessInfo>(m, "ProcessInfo")
        .def_readonly("eprocess", &dma::ProcessInfo::eprocess)
        .def_readonly("pid", &dma::ProcessInfo::pid)
        .def_readonly("cr3", &dma::ProcessInfo::cr3)
        .def_readonly("name", &dma::ProcessInfo::name);

    py::class_<dma::SymbolResolver>(m, "SymbolResolver")
        .def(py::init<dma::SymbolResolver::ReadCallback>())
        .def("get_process_list", &dma::SymbolResolver::get_process_list)
        .def("translate_virtual_to_physical", &dma::SymbolResolver::translate_virtual_to_physical);

    m.def("create_analysis", [](dma::DMAInterface* dma, dma::DumpManager* dump) {
        return std::make_unique<dma::StaticAnalyzer>(dma, dump);
    });
}
