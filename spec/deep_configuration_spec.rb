# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe Baseline::CiscoNxos::Parser do
  it "keeps a deeply nested irrelevant configuration from aborting baseline fact extraction" do
    text = "hostname LAB\n" + (0...4_000).map { |index| "#{' ' * index}unrelated\n" }.join
    parser = Baseline::CiscoNxos::Parser.new

    expect(text.bytesize).to be < 16 * 1024 * 1024
    result = parser.parse(text, complete: true)
    expect(result).to be_complete
    expect(result.records.first.fetch("facts").fetch("hostname")).to eq("LAB")
    expect(parser.cursor.state(0)).to eq(:parsed)
    expect(parser.cursor.states.drop(1)).to all(eq(:pending))
  end
end
