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

queue = []

list.each do |cve|
  uri = URI.parse("#{baseUrl}?id=#{cve}")

  t = Thread.new do
  response = Net::HTTP.get_response(uri)
  html = response.body
  parsed = Nokogiri::HTML.parse(html)
  path = %q(//table[@class="edit_form"]//tr[12]/td)
  node = parsed.xpath(path)
  severity = node.text.strip
  p "Request: #{cve} => #{severity}"
  dataMap[cve] = severity
  end
  queue << t
  if (queue.length >= 50)
      while currentThread = queue.shift
          currentThread.join
      end
  end
end

tb = CSV::Table.new []

data.each do |r|
  cve = r.field("CVE")
  severity = dataMap[cve]
  r.push({"Severity" => severity})
  tb << r
end


ctnt =  tb.to_csv write_headers: true

f = File.new("mapped3.csv", "w")
f.write(ctnt)
f.close
