
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "insia_vault/version"

Gem::Specification.new do |spec|
  spec.name          = "insia_vault"
  spec.version       = InsiaVault::VERSION
  spec.authors       = ["Jan Seďa"]
  spec.email         = ["git.work@hodor.cz"]

  spec.summary       = %q{Helper for vault-ruby.}
  spec.homepage      = "https://git.insia.com/insia_vault/"
#  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = ""
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "vault", ">= 0.10.1"
  spec.add_dependency "daemons", ">= 1.2.4"

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
end
