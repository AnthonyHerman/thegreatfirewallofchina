# Callback channels and metadata

The hard-deny list is the set of object-storage and cloud-API names below.
A host matches when it is the suffix or a subdomain of the suffix.
`notaliyuncs.com` does not match `aliyuncs.com`.

These are the places an agent phones home to a cloud account. They are not
a block of the `.cn` namespace, and they are not CDN edges. Alibaba CDN
names such as `*.w.alikunlun.com` and Tencent CDN names such as
`.cdn.dnsv1.com` stay off this list. An operator who means to call a
provider API adds that exact host to `allow_hosts`. Metadata addresses
cannot be allowlisted.

The proxy is opt-in. A process that ignores `HTTP_PROXY` does not pass
through it. Forcing egress is tracked as later work.

| Suffix or address | What it is | Source |
| --- | --- | --- |
| `aliyuncs.com` | Alibaba OSS and OpenAPI | [OSS domains](https://www.alibabacloud.com/help/en/oss/user-guide/access-oss-via-bucket-domain-name), [OpenAPI endpoints](https://www.alibabacloud.com/help/en/openapi/endpoints) |
| `myqcloud.com` | Tencent COS | [COS regions and endpoints](https://cloud.tencent.com/document/product/436/31315) |
| `tencentcos.cn` | Tencent COS intranet acceleration | [COS intranet acceleration](https://cloud.tencent.cn/document/product/436/56556) |
| `tencentcloudapi.com` | Tencent Cloud API | [API request structure](https://cloud.tencent.com/document/product/1278/46712) |
| `tencentyun.com` | Tencent metadata name | [CVM metadata](https://cloud.tencent.com/document/product/213/4934) |
| `bcebos.com` | Baidu BOS | [BOS endpoints](https://intl.cloud.baidu.com/en/doc/BOS/s/akrqd2wcx-intl-en) |
| `baidubce.com` | Baidu BCE API | [BCC endpoints](https://intl.cloud.baidu.com/zh/doc/BCC/s/4lu9gndm7-intl) |
| `myhuaweicloud.com`, `myhuaweicloud.cn` | Huawei OBS and API | [OBS endpoints](https://support.huaweicloud.com/en-us/devg-obs/obs_06_0007.html) |
| `volces.com`, `ivolces.com` | Volcengine TOS | [TOS regions](https://www.volcengine.com/docs/6349/107356) |
| `volcengineapi.com` | Volcengine OpenAPI | [Request structure](https://www.volcengine.com/docs/6369/67267) |
| `bytepluses.com`, `ibytepluses.com`, `bytepluses.com.cn`, `ibytepluses.com.cn` | BytePlus TOS | [TOS regions](https://docs.byteplus.com/en/docs/tos/docs-region-and-endpoint) |
| `byteplusapi.com` | BytePlus OpenAPI | [Request structure](https://docs.byteplus.com/zh-CN/docs/byteplus-platform/reference-request-structure) |
| `169.254.169.254` | AWS, GCP, Azure, and Huawei metadata | [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html), [GCP](https://docs.cloud.google.com/compute/docs/metadata/overview), [Azure](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service), [Huawei](https://support.huaweicloud.com/en-us/usermanual-ecs/ecs_03_0166.html) |
| `fd00:ec2::254` | AWS metadata, IPv6 | [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html) |
| `fd20:ce::254` | GCP metadata, IPv6 | [GCP](https://docs.cloud.google.com/compute/docs/metadata/overview) |
| `metadata.google.internal` | GCP metadata name | [GCP](https://docs.cloud.google.com/compute/docs/metadata/overview) |
| `100.100.100.200` | Alibaba metadata | [ECS metadata](https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/) |
| `100.96.0.96` | Volcengine and BytePlus metadata | [BytePlus metadata](https://docs.byteplus.com/en/docs/ecs/Viewing-instance-metadata) |

`169.254.0.0/16` and `fe80::/10` are denied as link-local. That range contains
the metadata addresses above. It is not a claim that every address in it was
listed by a vendor.

An explicit `allow_hosts` entry beats a provider suffix. It does not beat a
metadata address. Loopback is allowed so a local vLLM or similar server keeps
working. Other private ranges are denied unless `allow_private` is set. A raw
public IP is denied so a suffix rule cannot be skipped by dialing the address.
