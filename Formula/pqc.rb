class Pqc < Formula
  include Language::Python::Virtualenv

  desc "Post-Quantum Cryptography readiness scanner and connection monitor"
  homepage "https://github.com/The-CISO-Network/pqc"
  url "https://github.com/The-CISO-Network/pqc/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "2a2499e79be21a22819a1f18777002c783a300b013ddc0bab8685dcbf9823c76"
  license "MIT"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources using: "python3.12"
  end

  test do
    system bin/"pqc", "--help"
    system bin/"pqc", "scan", "--help"
  end
end
