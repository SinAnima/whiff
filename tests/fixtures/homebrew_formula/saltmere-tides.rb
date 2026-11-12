class SaltmereTides < Formula
  desc "Tide predictions for Saltmere Harbour"
  homepage "https://harbour.test/tides"
  url "https://harbour.test/releases/saltmere-tides-1.4.0.tar.gz"
  sha256 "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e"
  license "CC0-1.0"

  depends_on "pkgconf" => :build
  depends_on "glib"

  def install
    system "make", "install", "PREFIX=#{prefix}"
  end

  test do
    system bin/"tides", "--version"
  end
end
