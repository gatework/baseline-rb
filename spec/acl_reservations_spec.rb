# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe Baseline::AclReservations do
  it "matches zero-padded numbers and case variants without matching larger tokens or paths" do
    source = "feature 0002002\nowner acl_new\nother ACL_NEWER 12002 path/2003\n"
    result = described_class.from(configuration: source, identifiers: %w[2002 2003 ACL_NEW ACL_NO])
    expect(result).to eq(%w[2002 ACL_NEW])
  end

  it "retains only approved identities even when unrelated configuration tokens share their initial character" do
    result = described_class.from(configuration: "password cipher PRIVATE-AUTH-SEED\nreference POLICY\n", identifiers: %w[POLICY OTHER])
    expect(result).to eq([ "POLICY" ])
    expect(result.to_s).not_to include("PRIVATE-AUTH-SEED")
  end

  it "keeps independent matches among many candidates with a common prefix" do
    identifiers = 1000.times.map { |index| "ACL_#{index}" }
    result = described_class.from(configuration: "reference ACL_1 ACL_999 ACL_9999\n", identifiers: identifiers)
    expect(result).to eq(%w[ACL_1 ACL_999])
    expect(result).to be_frozen
  end
end
