from conan import ConanFile


class TidesConan(ConanFile):
    name = "saltmere-tides"
    version = "1.4.0"
    license = "CC0-1.0"
    url = "https://git.harbour.test/tides"
    description = "Tide predictions for Saltmere Harbour"
    settings = "os", "compiler", "build_type", "arch"

    def requirements(self):
        self.requires("fmt/11.0.2")
        self.tool_requires("cmake/3.30.1")
