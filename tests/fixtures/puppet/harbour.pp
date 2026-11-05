# Gauge daemon for the Saltmere Harbour hosts.
class harbour::gauge (
  String $station = 'north',
) {
  include harbour::common

  package { 'saltmere-gauge':
    ensure => installed,
  }

  service { 'gauged':
    ensure  => running,
    require => Package['saltmere-gauge'],
  }
}

node 'gauge01.harbour.test' {
  include harbour::gauge
}
