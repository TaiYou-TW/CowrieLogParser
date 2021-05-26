CREATE TABLE IF NOT EXISTS `simple_logs` (
  `id` int(11) NOT NULL auto_increment,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `ip` varchar(255) NOT NULL default '',
  `type` varchar(255) NOT NULL,
  `information` TEXT,
  PRIMARY KEY  (`id`),
) ;