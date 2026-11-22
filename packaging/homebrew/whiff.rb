# Homebrew Formula for whiff
#
class Whiff < Formula
  desc "Describe any file as one JSON document for people and LLMs"
  homepage "https://github.com/SinAnima/whiff"
  version "1.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-macos-aarch64.tar.gz"
      sha256 "a3b3a34b041bbd95fe159daf6b387c00b8fbcdb5490add0cf4531c732b268571"
    end
    on_intel do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-macos-x86_64.tar.gz"
      sha256 "7ef29d8c6920c158a935783324a866200c7f8ce4eeca8187efb21d94381b11d4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-linux-aarch64.tar.gz"
      sha256 "7bd31d6a321b82f5ee46f95610a60a28f59afa178e3a8cc325ea8b241ed32636"
    end
    on_intel do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-linux-x86_64.tar.gz"
      sha256 "7070c034ea5a353207d667624e7096dab748bb88a04fbc793e8e0cad7c1f81b0"
    end
  end

  def install
    bin.install "whiff"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/whiff --version")
  end
end
