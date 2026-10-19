# frozen_string_literal: true

require_relative "../multiline_document"

module Baseline
  module PaloAlto
    # PAN-OS 的 set 导出可能包含引号包裹的多行证书与描述。
    class Document < MultilineDocument
      protected

      # 已建模的多行值不能被误判为配置缺失；证书正文不参与语义分析。
      def multiline_fact?(text)
        /\Aset (?:deviceconfig system (?:hostname|service|permitted-ip|ntp-servers|snmp-setting|authentication-profile|route service)\b|shared (?:server-profile tacplus|authentication-profile|authentication-sequence|log-settings (?:syslog|profiles|system|config|userid|iptag|globalprotect|hipmatch|correlation))\b|mgt-config users\b|network (?:profiles interface-management-profile|interface)\b)/.match?(text) ||
          /\Aset (?:rulebase|vsys)\b.*\b(?:log-settings|log-setting|log-start|log-end|disabled)\b/.match?(text)
      end
    end
  end
end
