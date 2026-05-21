class Pqc < Formula
  include Language::Python::Virtualenv

  desc "Post-Quantum Cryptography readiness scanner and connection monitor"
  homepage "https://github.com/The-CISO-Network/pqc"
  url "https://github.com/The-CISO-Network/pqc.git",
      tag:      "v0.1.0",
      revision: "bfa28dd7cd3b0337564c47505d99f83b88308606"
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
