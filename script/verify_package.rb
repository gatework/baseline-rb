# frozen_string_literal: true

require "rubygems/package"
require "tmpdir"
require "rbconfig"

# 仅验证发布文件与解析后的依赖，避免从工作区加载代码。
artifact = File.expand_path(ARGV.fetch(0))
spec = Gem::Package.new(artifact).spec
abort "Unexpected package" unless spec.name == "baseline-rb"
abort "Unexpected package contents" if spec.files.any? { |path| path.start_with?("spec/", "test/", "storage/", "tmp/") || path.end_with?(".log", ".gem") }
Dir.mktmpdir("gem-install-") do |home|
  env = ENV.to_h.keys.grep(/\A(?:BUNDLE_|RUBY)/).to_h { |key| [ key, nil ] }
  env.merge!("GEM_HOME" => home, "GEM_PATH" => home, "RUBYOPT" => nil, "RUBYLIB" => nil)
  ruby = RbConfig.ruby
  system(env, ruby, "-S", "gem", "install", artifact, "--no-document", exception: true)
  check = <<~RUBY
    require "baseline"
    abort "Unexpected Rails dependency" if defined?(Rails)
    loaded = Gem.loaded_specs.fetch("baseline-rb")
    abort "Loaded checkout instead of package" unless File.realpath(loaded.full_gem_path).start_with?(File.realpath(ENV.fetch("GEM_HOME")) + "/")
    abort "Version mismatch" unless loaded.version.to_s == #{spec.version.to_s.inspect}
    default = Baseline::Policy.default
    abort "Bundled policy is missing its SNMP permission rule" unless default.rules.any? { |rule| rule.id == "snmp.write_enabled" && rule.expected == false }
    policy = Baseline::Policy.new("version" => 1, "checks" => { "ssh.enabled" => { "expected" => true } })
    audit = Baseline::Audit.new(policy: policy)
    source = "sysname PACKAGE-CHECK\\nssh server enable\\nreturn\\n"
    report = audit.call(configuration: source, platform: :h3c, complete: true)
    abort "Installed audit did not prove compliance" unless report.compliant? && report.findings.one? && report.configuration.value("ssh.enabled") == true
    abort "Partial evidence proved compliance" if audit.call(configuration: source, platform: :h3c).compliant?
    Dir[File.join(loaded.full_gem_path, "examples/**/*.rb")].sort.each { |path| load path }
  RUBY
  system(env, ruby, "-e", check, chdir: home, exception: true)
end
