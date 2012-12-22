#!/usr/bin/env ruby
# DESCRIPTION: updates the blocklists cached on disk from the sites listed in blocklists.
require 'timeout'

def rsync(bl,url)
	Timeout::timeout(300) {
		`#{$bindir}/rsync -a '#{url}'`	
	}
end

def curl(bl,url)
	Timeout::timeout(300) {
		`#{$bindir}/curl '#{url}' 2> /dev/null | sed 's/\\.0*/./g' | sed 's/^0*//' > #{$basedir}/#{bl}`
	}
end

def wget(bl,url)
	Timeout::timeout(300) {
		`#{$bindir}/wget --timeout=300 -q -O #{$basedir}/#{bl} '#{url}'`
	}
end

def spywaredomains_timestamp
	timestamp = `#{$bindir}/curl 'http://mirror1.malwaredomains.com/files/timestamp' 2> /dev/null`
	time = Time.at(timestamp)
end

if __FILE__ == $0
	$bindir = '/usr/bin'
	$basedir = File.dirname($0)
	if File.exists?("/opt/local/bin/wget")
		$bindir = '/opt/local/bin'
	end
	thr = []
	blocklists = File.open("#{$basedir}/blocklists").readlines.map {|l| l.chomp}
	blocklists.each do |bl|
		bl, url = bl.split(/ /,2)
		thr << Thread.new(bl,url) do |bl, url|
			begin
				if bl == "surriel"
					rsync(bl,url)
				elsif bl == "dshield"
					curl(bl,url)
				elsif bl == "maldom"
					ts = spywaredomains_timestamp
					if File.exists?("maldom")
						ts2 = File.stat("maldom").mtime
					end
					if ts2 == nil or ts > ts2
						wget(bl,url)
					end
				else
					wget(bl,url)
				end
			rescue Exception => e
				puts "Error updating #{bl}: #{e}"
			end
		end
	end
	thr.each do |t| t.join end
end