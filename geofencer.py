from subprocess import call
import sys, os
import csv
import optparse

""" This program geofences PPI-enabled PCAPs to a particular set of coordinates, extending out to either a small or large radius (small = 200m, large = 400m), then cross-correlates probe requests from a different geospatial reference point for commonalities.

(ELI5 Version: Sees if devices from one area have been in another.)

PCAP will have to have GPS coordinates in a PPI header

Will produce 5 files: geofenced, accesspoints, probes, accesspoints.csv, probes.csv

You can also correlate probes seen in one area to APs seen in another. """


def tshark_filterpcap(ifile, read_filter, ofile):
	call(['tshark', '-2', '-F', 'pcap', '-r', ifile, '-R', read_filter, '-w', ofile])

def find_commons(probedb_csv, accesspointcsv):
	probes = set()
	aps = set()
	probereader = csv.reader(open(probedb_csv, 'r'), delimiter=',')
	apreader = csv.reader(open(accesspointcsv, 'r'), delimiter=',')

	for row in probereader:
	    try:
	        ssid = row[1]
	        probes.add(ssid)
	    except:
	        pass
	for row in apreader:
	    try:
	        ssid = row[1]
	        aps.add(ssid)
	    except:
	        pass

	commons = probes.intersection(aps)
	return commons

parser = optparse.OptionParser('usage%prog ' + '-f <infile> -c <coordinates> -r <radius> -p <prefix> -P <probecorrelationfile>')
parser.add_option('-f', dest='infile', type='string', help='specify capture file to be parsed')
parser.add_option('-c', dest='coords', type='string', help='specify centerpoint coordinates of area to be geofenced as lat long')
parser.add_option('-r', dest='radius', type='string', help='specify large or small radius for geofence')
parser.add_option('-p', dest='prefix', type='string', help='specify prefix name for geofenced area (usually address or other identifier)')
parser.add_option('-P', dest='probecorrelationfile', type='string', help='if you wish to perform probe correlation for probes referencing SSIDs in your geofence area, specify CSV file containing probes with MAC,SSID as columns')

(options, args) = parser.parse_args()

infile = options.infile
coords = options.coords
radius = options.radius
prefix = options.prefix
probecorrelationfile = options.probecorrelationfile

lat = float(coords.split(' ')[0])
lng = float(coords.split(' ')[1])

# generate bounding coordinates
if radius == 'small':
	lowlat = lat - .0010
	highlat = lat + .0010
	lowlng = lng - .0010
	highlng = lng + .0010
elif radius == 'large':
	lowlat = lat - .0020
	highlat = lat + .0020
	lowlng = lng - .0020
	highlng = lng + .0020

# open full capture file
fullcapture = infile

# generate tshark geofence filter query, apply, and save w/ prefix+geofenced.pcap
if radius == 'small':
	print '[+] Generating PCAP of all packets within 200m radius of ' + str(coords) + '.'
elif radius == 'large':
	print '[+] Generating PCAP of all packets within 400m radius of ' + str(coords) + '.'

tsharkgeofence = '((ppi_gps.lon <= %f) && (ppi_gps.lon >=  %f) && (ppi_gps.lat >= %f) && (ppi_gps.lat <= %f))' %(highlng, lowlng, lowlat, highlat)
geo_outpcap = prefix + '_geofenced.pcap'
tshark_filterpcap(fullcapture, tsharkgeofence, geo_outpcap)

# apply tshark probe filter, apply, save probes pcap w/ prefix+probes.pcap
if radius == 'small':
	print '[+] Generating PCAP of all probe requests within 200m radius of ' + str(coords) + '.'
elif radius == 'large':
	print '[+] Generating PCAP of all probe requests within 400m radius of ' + str(coords) + '.'
probefilter = 'wlan.fc.type_subtype eq 4'
probe_outpcap = prefix + '_probes.pcap'
tshark_filterpcap(geo_outpcap, probefilter, probe_outpcap)

# apply tshark beacon filter for aps, save ap pcap w/ prefix+accesspoints.pcap
if radius == 'small':
	print '[+] Generating PCAP of all beacon frames within 200m radius of ' + str(coords) + '.'
elif radius == 'large':
	print '[+] Generating PCAP of all beacon frames within 400m radius of ' + str(coords) + '.'
beaconfilter = 'wlan.fc.type_subtype eq 8'
beacon_outpcap = prefix + '_accesspoints.pcap'
tshark_filterpcap(geo_outpcap, beaconfilter, beacon_outpcap)

# open probes pcap, save mac, ssids being probed for, and lat/long as csv using prefix+probes.csv
print '[+] Generating CSV of probes.'
probecsvfile = prefix + '_probes.csv'
call('tshark -r "%s" -T fields -e wlan.sa -e wlan_mgt.ssid -e ppi_gps.lat -e ppi_gps.lon -E header=y -E separator=, > "%s"' %(probe_outpcap,probecsvfile), shell=True)

# remove broadcasts from probecsvfile and dedupe
probecsv_cleaned = probecsvfile +'_cleaned.csv'
reader = csv.reader(open(probecsvfile, 'r'), delimiter=',')
writer = csv.writer(open(probecsv_cleaned, 'w'), delimiter=',')
next(reader)

entries = set()
for row in reader:
	key = (row[0], row[1])
	if key not in entries:
		if row[1] != '':
			writer.writerow(row)
		entries.add(key)	


# open access points pcap, save mac, ssid, and lat/long as csv using prefix+accesspoints.csv
print '[+] Generating CSV of access points.'
beaconcsvfile = prefix + '_accesspoints.csv'
call('tshark -r "%s" -T fields -e wlan.sa -e wlan_mgt.ssid -e ppi_gps.lat -e ppi_gps.lon -E header=y -E separator=, > "%s"' %(beacon_outpcap,beaconcsvfile), shell=True)

# dedupe
beaconcsv_cleaned = beaconcsvfile +'_cleaned.csv'
reader2 = csv.reader(open(beaconcsvfile, 'r'), delimiter=',')
writer2 = csv.writer(open(beaconcsv_cleaned, 'w'), delimiter=',')
next(reader2)

entries2 = set()
for row in reader2:
	key2 = (row[0], row[1])
	if key2 not in entries2:
		writer2.writerow(row)
		entries2.add(key2)

if probecorrelationfile != None:
	print "[+] Correlating probes from reference area to APs near " + str(coords) + '.'
	#probe_bank = 'SFOProbes_deduped.csv'
	probe_bank = probecorrelationfile
	commons = find_commons(probe_bank, beaconcsv_cleaned)
	print "[+] The following SSIDs near your coordinates were being probed for: "
	print '\n'.join(list(commons))

call('mkdir %s' %(prefix), shell=True)
call('mv %s %s %s %s %s ./%s' %(geo_outpcap, probe_outpcap, beacon_outpcap, probecsv_cleaned, beaconcsv_cleaned, prefix), shell=True)
#os.chdir('./%s' %(prefix), shell=True)
call('rm %s %s' %(probecsvfile, beaconcsvfile), shell=True)
