# CHANGELOG - kubernetes

## 1.7.0 / 2020-05-17

* [Added] Allow optional dependency installation for all checks. See [#6589](https://github.com/DataDog/integrations-core/pull/6589).

## 1.6.0 / 2020-01-13

* [Added] Use lazy logging format. See [#5377](https://github.com/DataDog/integrations-core/pull/5377).

## 1.5.1 / 2018-09-04

* [Fixed] Add data files to the wheel package. See [#1727][1].
* [Fixed] Only calculate filesystem usage when capacity is greater than 0. See [#1606][2]. Thanks [aaronbbrown][3].

## 1.5.0 / 2017-10-10

* [IMPROVEMENT] remove namespace from pod_name tag. See [#770][4]
* [BUGFIX] stop reporting cAdvisor metrics about non-container objects. See [#770][4]

## 1.4.0 / 2017-09-12

* [FEATURE] Add an option to retry kubelet connection if it's not up at start time. See [#722][5]
* [BUGFIX] fix container_image names reported as sha checksums [#731][6]

## 1.3.0 / 2017-08-28

* [FEATURE] add an option to collect node labels as host tags. See [#614][7]
* [IMPROVEMENT] add custom tags to service checks [#642][8]
* [FEATURE] skip cAdvisor metrics if port is set to 0. See [#655][9]
* [FEATURE] enable event collection according to agent leader status. See [#687][10]

## 1.2.0 / 2017-07-18

* [FEATURE] allow to configure kubelet and apiserver urls and credentials to run directly on the host. See [#508][11]
* [IMPROVEMENT] query kubernetes service mapping every 5 minutes to reduce apiserver traffic (see service_tag_update_freq option) and add collect_service_tags option to disable it completely. See [#476][12]
* [IMPROVEMENT] Fix typo in exception reporting when unable to collect metrics for a container. See [#493][13]
* [BUGFIX] fix failures when the spec has "has_filesystem" entry but no stats entry for filesystem. See [#494][14]
* [BUGFIX] don't fail if cadvisor is unreachable, send integration warning and send other metrics. See [#538][15]

## 1.1.0 / 2017-06-05

* [FEATURE] Make the pod label to tag prefix configurable. See [dd-agent-3345][16]
* [IMPROVEMENT] Report a service check when the Kubelet daemon is unreachable. See [#350][17]
* [IMPROVEMENT] Add service and creator (deployment/daemon_set/replica_set/job) tags to kube.* and docker.* metrics. See [#319][18] and [#434][19]
* [IMPROVEMENT] Add custom tags to events. See [#449][20]
* [BUGFIX] Fix missing docker.net metrics in Kubernetes. See [#418][21]

## 1.0.0 / 2017-02-23

* [FEATURE] adds Kubernetes integration.

<!--- The following link definition list is generated by PimpMyChangelog --->
[1]: https://github.com/DataDog/integrations-core/pull/1727
[2]: https://github.com/DataDog/integrations-core/pull/1606
[3]: https://github.com/aaronbbrown
[4]: https://github.com/DataDog/integrations-core/issues/770
[5]: https://github.com/DataDog/integrations-core/issues/722
[6]: https://github.com/DataDog/integrations-core/issues/731
[7]: https://github.com/DataDog/integrations-core/issues/614
[8]: https://github.com/DataDog/integrations-core/issues/642
[9]: https://github.com/DataDog/integrations-core/issues/655
[10]: https://github.com/DataDog/integrations-core/issues/687
[11]: https://github.com/DataDog/integrations-core/issues/508
[12]: https://github.com/DataDog/integrations-core/issues/476
[13]: https://github.com/DataDog/integrations-core/issues/493
[14]: https://github.com/DataDog/integrations-core/issues/494
[15]: https://github.com/DataDog/integrations-core/issues/538
[16]: https://github.com/DataDog/dd-agent/pull/3345
[17]: https://github.com/DataDog/integrations-core/issues/350
[18]: https://github.com/DataDog/integrations-core/issues/319
[19]: https://github.com/DataDog/integrations-core/issues/434
[20]: https://github.com/DataDog/integrations-core/issues/449
[21]: https://github.com/DataDog/integrations-core/issues/418
