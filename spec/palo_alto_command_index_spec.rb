# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe "Baseline PAN-OS statement index" do
  let(:index_class) { Baseline::PaloAlto.const_get(:CommandIndex, false) }

  it "preserves complete prefix matching and order beyond indexed levels" do
    tokens = %w[a b c d e f g h i]
    rows = [ { tokens: tokens, id: 1 }, { tokens: tokens.take(7) + %w[x i], id: 2 },
      { tokens: tokens + [ "tail" ], id: 3 }, { tokens: tokens, id: 4 }, { tokens: [ "a b" ], id: 5 } ]
    index = index_class.new(rows)
    [ [], [ "a" ], [ "a b" ], tokens.take(7), tokens.take(8), tokens, tokens + [ "tail" ],
      tokens + [ "missing" ], tokens + %w[tail missing] ].each do |prefix|
      expect(index.matching_prefix(prefix)).to eq(rows.select { |row| row[:tokens].take(prefix.size) == prefix })
    end
  end

  it "bounds indexing allocations for a malformed statement with a large scalar tail" do
    rows = [ { tokens: %w[mgt-config users SYNTHETIC phash] + Array.new(10_000, "x") } ]
    index_class.new([])
    allocated = GC.stat(:total_allocated_objects)
    index = index_class.new(rows)
    allocated = GC.stat(:total_allocated_objects) - allocated
    expect(index.matching_prefix(%w[mgt-config users SYNTHETIC phash])).to eq(rows)
    expect(allocated).to be < 1_000
  end
end
