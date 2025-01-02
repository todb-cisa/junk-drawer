#!/usr/bin/env ruby

require 'net/http'
require 'json'
require 'date'
require 'optparse'
require 'base64'

def parse_options
  options = {}
  OptionParser.new do |opts|
    opts.on('--since DATE', 'Display vulnerabilities since this date (format: YYYY-MM-DD)') do |date|
      options[:since] = Date.parse(date)
    end

    opts.on('--added', 'Show the added date instead of the due date') do
      options[:added] = true
    end

    opts.on('--due', 'Show the due date (default behavior)') do
      options[:due] = true
    end

    opts.on('--fresh', 'Display entries with due dates today or in the future') do
      options[:fresh] = true
    end

    opts.on('-h', '--help', 'Show this message') do
      puts opts
      exit
    end
  end.parse!
  options
end

options = parse_options

since_date = options[:since] || (Date.today - (Date.today.wday + 2) % 7)
since_day = since_date.strftime("%A")

def fetch_vuln_data
  url = 'https://raw.githubusercontent.com/todb/kev-lite/refs/heads/main/cisa.json'
  uri = URI(url)
  response = Net::HTTP.get(uri)
  JSON.parse(response)
end

def filter_vulns(vuln_data, since_date, options)
  if options[:fresh]
    vuln_data['vulnerabilities'].select do |vuln|
      Date.parse(vuln['dueDate']) >= Date.today
    end
  else
    vuln_data['vulnerabilities'].select do |vuln|
      Date.parse(vuln['dateAdded']) >= since_date
    end
  end
end

def print_status_line(since_date, recent_vulns, options)
  kev_count = recent_vulns.size
  kev_label = kev_count == 1 ? 'KEV' : 'KEVs'

  if options[:fresh]
    puts "[*] Displaying #{kev_count} #{kev_label} with due dates today or in the future"
  elsif kev_count == 0
    puts "[*] No KEVs added since #{since_date} (#{since_date.strftime('%A')})"
  else
    puts "[*] Displaying #{kev_count} #{kev_label} since #{since_date} (#{since_date.strftime('%A')})"
  end
end

def print_kevs(recent_vulns, options)
  recent_vulns.each do |vuln|
    cve_id = vuln['cveID']
    vuln_name = vuln["vulnerabilityName"].sub(/ Vulnerability\s*/, '')
    added_date = vuln['dateAdded']
    due_date = vuln['dueDate']

    if options[:added] && options[:due]
      puts "#{cve_id} #{vuln_name} (Added: #{added_date} Due: #{due_date})"
    elsif options[:added]
      puts "#{cve_id} #{vuln_name} (Added: #{added_date})"
    else
      puts "#{cve_id} #{vuln_name} (Due: #{due_date})"
    end
  end
end

vuln_data = fetch_vuln_data()
recent_vulns = filter_vulns(vuln_data, since_date, options)
recent_vulns.sort_by! { |vuln| [Date.parse(vuln['dateAdded']), vuln["vulnerabilityName"]] }.reverse!

print_status_line(since_date, recent_vulns, options)
print_kevs(recent_vulns, options)
