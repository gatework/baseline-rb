# frozen_string_literal: true

module Baseline
  # 已建模的时间关联语法；认证密钥只能保留既有引用，不能由此创建秘密。
  module NtpCommands
    private

    def render_ntp(operation, verified_key_ids: [], verified_slots: [], syntax_profile: nil)
      identity, scope = operation.identity, operation.scope
      unless identity.keys.sort == %w[address role] && scope.keys == [ "vrf" ] && %w[server peer].include?(identity["role"])
        raise CommandRenderer::UnsupportedOperation, "unsupported_ntp_identity"
      end
      address, role, vrf = identity.fetch("address"), identity.fetch("role"), scope.fetch("vrf")
      if /[\[\]%]/.match?(address) || %w[vrf ip ipv6 vpn-instance].include?(address.downcase)
        raise ArgumentError, "Invalid NTP target spelling"
      end
      style = self.class::NTP_STYLE
      if syntax_profile && !(style == :h3c && %w[comware_legacy comware7].include?(syntax_profile) || style == :vrp && syntax_profile == "vrp_s_series")
        raise CommandRenderer::UnsupportedOperation, "unsupported_ntp_syntax_profile"
      end
      comware = %i[h3c vrp].include?(style)
      if style == :vrp
        ip = begin
          IPAddr.new(address)
        rescue IPAddr::Error
          nil
        end
        raise CommandRenderer::UnsupportedOperation, "unsupported_vrp_ntp_address" unless ip
      end
      prefix = comware ? "ntp-service #{style == :h3c && address.include?(':') ? 'ipv6 ' : ''}unicast-#{role}" : "ntp #{role}"
      target = if style == :vrp
        "#{prefix} #{address.include?(':') ? 'ipv6 ' : ''}#{address}#{vrf == 'default' ? '' : " vpn-instance #{vrf}"}"
      elsif style == :h3c && syntax_profile == "comware7"
        "#{prefix} #{address}#{vrf == 'default' ? '' : " vpn-instance #{vrf}"}"
      elsif comware
        "#{prefix} #{vrf == 'default' ? '' : "vpn-instance #{vrf} "}#{address}"
      elsif style == :ios
        "#{prefix} #{vrf == 'default' ? '' : "vrf #{vrf} "}#{address.include?(':') ? 'ipv6 ' : ''}#{address}"
      else
        "#{prefix} #{address}#{vrf == 'default' ? '' : " use-vrf #{vrf}"}"
      end
      commands = []
      commands << "#{comware ? 'undo' : 'no'} #{target}" if %i[remove replace].include?(operation.action)
      if operation.after
        fields = operation.after
        allowed = comware ? %w[version key_id prefer source] : %w[version key_id prefer source minpoll maxpoll burst iburst normal_sync]
        raise CommandRenderer::UnsupportedOperation, "unsupported_ntp_options" unless (fields.keys - allowed).empty?
        if (style == :vrp || style == :h3c && syntax_profile == "comware7") && address.include?(":") && fields.key?("version")
          raise CommandRenderer::UnsupportedOperation, "unsupported_ipv6_ntp_version"
        end
        if %w[prefer burst iburst normal_sync].any? { |field| fields[field] == false }
          raise CommandRenderer::UnsupportedOperation, "implicit_ntp_option_state_unverified"
        end
        unless verified_key_ids.is_a?(Array) && verified_key_ids.all? { |key| key.is_a?(Integer) && key.between?(1, 4_294_967_295) }
          raise ArgumentError, "Invalid verified NTP key identities"
        end
        if fields.key?("key_id") && operation.before&.fetch("key_id", nil) != fields["key_id"] && !verified_key_ids.include?(fields["key_id"])
          raise CommandRenderer::UnsupportedOperation, "ntp_key_material_unverified"
        end
        tail = []
        tail << "version #{fields['version']}" if fields.key?("version")
        tail << "#{comware ? 'authentication-keyid' : 'key'} #{fields['key_id']}" if fields.key?("key_id")
        tail << (style == :vrp ? "preference" : comware ? "priority" : "prefer") if fields["prefer"] == true
        if fields.key?("source")
          interface = ResourceSchema.interface_name(fields["source"])
          raise ArgumentError, "Invalid NTP source interface" unless interface
          tail << "#{comware && syntax_profile != 'comware7' ? 'source-interface' : 'source'} #{interface}"
        end
        %w[minpoll maxpoll].each { |key| tail << "#{key} #{fields[key]}" if fields.key?(key) }
        %w[burst iburst normal_sync].each { |key| tail << key.tr("_", "-") if fields[key] == true }
        if fields.key?("minpoll") && fields.key?("maxpoll") && fields["minpoll"] > fields["maxpoll"]
          raise ArgumentError, "Invalid NTP polling interval"
        end
        commands << [ target, *tail ].join(" ")
      end
      commands.map { |command| CommandStep.new(view: [], command: command, phase: operation.phase, operation_id: operation.id) }
    end
  end
end
