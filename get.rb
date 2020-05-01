#!/usr/bin/env ruby

require "fileutils"
require "csv"
require "net/http"
require 'nokogiri'

content = File.read("data.csv");

data = CSV.parse(content, headers: true)

baseUrl = "https://bugzilla.redhat.com/show_bug.cgi"

dataMap = {}

list = []

data.each do |r|
  cve = r.field("CVE")  
  list << cve
end

list.uniq!

list.each do |cve|
  uri = URI.parse("#{baseUrl}?id=#{cve}")

  response = Net::HTTP.get_response(uri)
  html = response.body
  parsed = Nokogiri::HTML.parse(html)
  path = %q(//table[@class="edit_form"]//tr[12]/td)
  node = parsed.xpath(path)
  severity = node.text.strip
  dataMap[cve] = severity
end

mapped = data.map do |r|
  cve = r.field("CVE")
  severity = dataMap[cve]
  r.push({"Severity" => severity})
  p "#{cve} => #{severity}"
  r
end

ctnt =  mapped.to_s(write_headers: true)

f = File.new("mapped.csv", "w")
f.write(ctnt)
f.close
