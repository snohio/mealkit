# frozen_string_literal: true

# All attributes are set here - default is all enabled.
default['remediation_stig_ubuntu2004_v1_2_0']['attributes'] = {
  "provider": "STIG",
  "benchmark": "Ubuntu2004",
  "benchmark_platform": "debian",
  "provider_version": "v1.2.0",
  "global_environment": {
  },
  "controls": [
    {
      "id": "STIG_Ubuntu2004_SV_238200r653775",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238201r653778",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238202r653781",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238203r653784",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238204r653787",
      "enabled": true,
      "environment": [
        {
          "name": "GRUB_PASSWORD",
          "default": "passwd@123"
        }
      ]
    },
    {
      "id": "STIG_Ubuntu2004_SV_238208r653799",
      "enabled": false
    },
    {
      "id": "STIG_Ubuntu2004_SV_238209r653802",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238210r653805",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238211r653808",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238212r653811",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238213r653814",
      "enabled": false
    },
    {
      "id": "STIG_Ubuntu2004_SV_238216r654316",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238217r653826",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238218r653829",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238219r653832",
      "enabled": false
    },
    {
      "id": "STIG_Ubuntu2004_SV_238220r653835",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238221r653838",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238222r653841",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238223r653844",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238224r653847",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238225r653850",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238226r653853",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238227r653856",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238228r653859",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238229r653862",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238230r653865",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238231r653868",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238232r653871",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238233r653874",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238235r802383",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238237r653886",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238238r653889",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238239r653892",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238240r653895",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238241r653898",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238242r653901",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238244r653907",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238249r653922",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238250r653925",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238251r653928",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238252r653931",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238253r653934",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238254r653937",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238255r653940",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238256r653943",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238257r653946",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238258r808474",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238264r808477",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238268r808480",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238271r808483",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238277r654006",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238278r654009",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238279r654012",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238280r654015",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238281r654018",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238282r654021",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238283r654024",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238284r654027",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238285r654030",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238286r654033",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238287r654036",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238288r654039",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238289r654042",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238290r654045",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238291r654048",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238292r654051",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238293r654054",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238294r654057",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238295r808486",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238297r802387",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238298r654069",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238299r654072",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238300r654075",
      "enabled": true,
      "manual": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238301r654078",
      "enabled": true,
      "manual": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238302r654081",
      "enabled": true,
      "manual": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238304r654087",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238310r808489",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238315r654120",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238316r654123",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238317r654126",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238318r654129",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238319r654132",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238320r654135",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238323r654144",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238325r654150",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238326r654153",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238327r654156",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238330r654165",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238333r654174",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238337r654186",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238338r654189",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238339r654192",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238340r654195",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238341r654198",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238342r654201",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238343r654204",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238354r654237",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238357r654246",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238359r654319",
      "enabled": true,
      "manual": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238363r654320",
      "enabled": true,
      "manual": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238369r654282",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238370r654285",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238371r654288",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_238373r654294",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_251503r808506",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_251504r808509",
      "enabled": true
    },
    {
      "id": "STIG_Ubuntu2004_SV_251505r808512",
      "enabled": true
    }
  ]
}
# Note - the cookbook will perform remediation by default for all controls. Add the below to instead perform a dry-run.
#default['remediation_stig_ubuntu2004_v1_2_0']['attributes']['dry_run'] = true