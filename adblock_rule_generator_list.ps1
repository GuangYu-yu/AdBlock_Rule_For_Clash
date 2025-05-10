# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0

# 定义广告过滤器URL列表
$urlList = @(
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_18_Annoyances_Cookies/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_19_Annoyances_Popups/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_20_Annoyances_MobileApp/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_21_Annoyances_Other/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_22_Annoyances_Widgets/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_101_EasyList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_104_EasyListChina/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_118_EasyPrivacy/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_122_FanboysAnnoyances/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_123_FanboysSocialBlockingList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_201_WebAnnoyancesUltralist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_204_PeterLowesList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_207_AdblockWarningRemovalList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_208_Online_Malicious_URL_Blocklist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_209_ADgkMobileChinalist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_210_Spam404/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_211_AntiAdblockKillerReek/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_219_ChinaListAndEasyList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_220_CJXsAnnoyanceList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_228_xinggsf/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_229_IdontCareAboutCookies/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_239_FanboyAntifonts/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_240_BarbBlock/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_241_FanboyCookiemonster/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_242_NoCoin/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_255_Phishing_URL_Blocklist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_256_Scam_Blocklist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_257_uBlock_Origin_Badware_risks/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/foreign.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/cryptominers.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/allowlist.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/allowlist_stealth.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/antiadblock.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/replace.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/content_blocker.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exclusions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exceptions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/rules.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/popups.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/social_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/allowlist_app.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/allowlist_web.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_specific.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/general_url.txt",
"https://filters.adtidy.org/extension/chromium/filters/15.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_7_Japanese/filter.txt",
"https://big.oisd.nl",
"https://neodev.team/adblocker",
"https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
"https://raw.githubusercontent.com/damengzhu/abpmerge/main/abpmerge.txt",
"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
"https://raw.githubusercontent.com/lingeringsound/10007/main/all",
"https://raw.githubusercontent.com/lingeringsound/adblock_auto/main/Rules/adblock_auto.txt",
"https://raw.githubusercontent.com/uniartisan/adblock_list/refs/heads/master/adblock_plus.txt",
"https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock_plus.txt",
"https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
"https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt",
"https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt",
"https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt",
"https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt",
"https://adaway.org/hosts.txt",
"https://hblock.molinero.dev/hosts",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
"https://raw.githubusercontent.com/rentianyu/Ad-set-hosts/master/adguard",
"https://raw.githubusercontent.com/lpmasser/AdBlock_Rule_For_Clash/refs/heads/main/Fuck_MIUI.txt",
"https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
"https://raw.githubusercontent.com/Bibaiji/ad-rules/main/rule/local-rule.txt",
"https://raw.githubusercontent.com/YanFung/Ads/master/Mobile",
"https://raw.githubusercontent.com/greatcoolge/HyperADRules/master/list/allow1.txt",
"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
"https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt",
"https://raw.githubusercontent.com/Lynricsy/HyperADRules/master/rules.txt",
"https://raw.githubusercontent.com/runningcheese/RunningCheese-Firefox/refs/heads/master/Restore/Adblock_Popup.txt",
"https://raw.githubusercontent.com/runningcheese/RunningCheese-Firefox/refs/heads/master/Restore/Adblock_Watermark.txt",
"https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/refs/heads/master/minority-mv.txt",
"https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/refs/heads/master/mv.txt",
"https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/refs/heads/master/rule.txt",
"https://raw.githubusercontent.com/cjx82630/cjxlist/refs/heads/master/cjx-annoyance.txt",
"https://raw.githubusercontent.com/cjx82630/cjxlist/refs/heads/master/cjx-ublock.txt",
"https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker",
"https://raw.githubusercontent.com/lingeringsound/10007/main/adb.txt"
)

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"

# 创建两个HashSet来存储唯一的规则和排除的域名
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new()

# 创建WebClient对象用于下载规则
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

# DNS规范验证函数
function Is-ValidDNSDomain($domain) {
    if ($domain.Length -gt 253) { return $false }
    $labels = $domain -split "\."
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$") {
            return $false
        }
    }
    $tld = $labels[-1]
    if ($tld -notmatch "^[a-zA-Z]{2,}$") { return $false }
    return $true
}

# 创建临时文件夹来存储下载的文件
$tempDir = Join-Path $PSScriptRoot "temp_rules"
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}

# 第一步：下载所有规则文件
Write-Host "`n=== 第一步：下载所有规则文件 ===" -ForegroundColor Green
Write-Host "开始下载规则文件..."
$downloadedFiles = @()
$totalUrls = $urlList.Count
$currentUrl = 0

foreach ($url in $urlList) {
    $currentUrl++
    try {
        # 生成唯一的文件名
        $urlHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($url)
        )
        $urlHashString = [System.BitConverter]::ToString($urlHash).Replace("-", "").Substring(0, 8)
        
        $fileName = [System.IO.Path]::GetFileName($url)
        if ([string]::IsNullOrEmpty($fileName)) {
            $fileName = "rule_$urlHashString.txt"
        } else {
            # 在文件名和扩展名之间插入哈希值
            $fileNameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
            $fileExt = [System.IO.Path]::GetExtension($fileName)
            $fileName = "${fileNameWithoutExt}_${urlHashString}${fileExt}"
        }
        
        $filePath = Join-Path $tempDir $fileName
        
        Write-Host "[$currentUrl/$totalUrls] 正在下载: $url" -ForegroundColor Cyan
        Add-Content -Path $logFilePath -Value "正在下载: $url"
        
        $webClient.DownloadFile($url, $filePath)
        $downloadedFiles += $filePath
        
        Write-Host "下载完成: $fileName" -ForegroundColor Green
    }
    catch {
        Write-Host "下载 $url 时出错: $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "下载 $url 时出错: $_"
    }
}

Write-Host "`n下载完成，共下载 $($downloadedFiles.Count) 个文件" -ForegroundColor Green

# 第二步：处理下载的文件
Write-Host "`n=== 第二步：处理规则文件 ===" -ForegroundColor Green
$totalFiles = $downloadedFiles.Count
$currentFile = 0

foreach ($filePath in $downloadedFiles) {
    $currentFile++
    $fileName = Split-Path $filePath -Leaf
    Write-Host "[$currentFile/$totalFiles] 正在处理文件: $fileName" -ForegroundColor Cyan
    Add-Content -Path $logFilePath -Value "正在处理文件: $fileName"
    
    try {
        $content = Get-Content -Path $filePath -Raw
        $lines = $content -split "`n"
        
        foreach ($line in $lines) {
            # 直接处理以 @@ 开头的规则，提取域名并加入白名单
            if ($line.StartsWith('@@')) {
                $domains = $line -replace '^@@', '' -split '[^\w.-]+'
                foreach ($domain in $domains) {
                    if (-not [string]::IsNullOrWhiteSpace($domain) -and $domain -match '[\w-]+(\.[[\w-]+)+') {
                        $excludedDomains.Add($domain.Trim()) | Out-Null
                    }
                }
            }
            else {
                # 修改正则匹配部分
                # 匹配 ||domain.com^ 格式的规则（作为DOMAIN-SUFFIX处理）
                if ($line -match '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^') {
                    $domain = $Matches[1]
                    $uniqueRules.Add("*.$domain") | Out-Null  # 添加*. 前缀表示这是一个DOMAIN-SUFFIX规则
                }
                # 匹配 Hosts 文件格式（作为DOMAIN处理）
                elseif ($line -match '^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[2]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 IPv6 格式（作为DOMAIN处理）
                elseif ($line -match '^::(1)?\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[2]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Dnsmasq 格式（作为DOMAIN-SUFFIX处理）
                elseif ($line -match '^(address|server)=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
                    $domain = $Matches[2]
                    $uniqueRules.Add("*.$domain") | Out-Null
                }
                # 处理纯域名行
                elseif ($line -match '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
            }
        }
    }
    catch {
        Write-Host "处理文件 $fileName 时出错: $_" -ForegroundColor Red
        Add-Content -Path $logFilePath -Value "处理文件 $fileName 时出错: $_"
    }
}

# 清理临时文件
Write-Host "`n清理临时文件..."
Remove-Item -Path $tempDir -Recurse -Force

# 在写入文件之前进行DNS规范验证
$validRules = [System.Collections.Generic.HashSet[string]]::new()
$validExcludedDomains = [System.Collections.Generic.HashSet[string]]::new()

foreach ($domain in $uniqueRules) {
    if (Is-ValidDNSDomain($domain)) {
        $validRules.Add($domain) | Out-Null
    }
}

foreach ($domain in $excludedDomains) {
    if (Is-ValidDNSDomain($domain)) {
        $validExcludedDomains.Add($domain) | Out-Null
    }
}

# 排除所有白名单规则中的域名
$finalRules = $validRules | Where-Object { -not $validExcludedDomains.Contains($_) }

# 修改格式化规则的部分
$domainRules = [System.Collections.Generic.List[string]]::new()
$domainSuffixRules = [System.Collections.Generic.List[string]]::new()

foreach ($rule in $finalRules) {
    if ($rule.StartsWith('*.')) {
        # 对于带有*. 前缀的规则，移除前缀并作为DOMAIN-SUFFIX
        $cleanDomain = $rule.Substring(2)
        $domainSuffixRules.Add("DOMAIN-SUFFIX,$cleanDomain")
    }
    else {
        # 没有*. 前缀的规则作为DOMAIN
        $domainRules.Add("DOMAIN,$rule")
    }
}

# 分别对两种规则进行排序
$domainRules = $domainRules | Sort-Object
$domainSuffixRules = $domainSuffixRules | Sort-Object

# 合并排序后的规则，直接输出规则内容，不添加额外格式
$formattedRules = @()
$formattedRules += $domainRules
$formattedRules += $domainSuffixRules

# 统计生成的规则条目数量
$ruleCount = $finalRules.Count

# 获取当前时间并转换为东八区时间
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 在处理规则之前，先下载参考文件并创建一个规则集合
Write-Host "`n=== 下载参考文件 ===" -ForegroundColor Green
$referenceUrls = @(
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Advertising/Advertising.list",
    "https://raw.githubusercontent.com/GuangYu-yu/ACL4SSR/refs/heads/main/REJECT.list",
    "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_ad_only.conf"
)

$referenceRules = [System.Collections.Generic.HashSet[string]]::new()

foreach ($url in $referenceUrls) {
    try {
        Write-Host "正在下载参考文件: $url" -ForegroundColor Cyan
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"
        foreach ($line in $lines) {
            $referenceRules.Add($line.Trim()) | Out-Null
        }
    }
    catch {
        Write-Host "下载参考文件失败: $url" -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
}

Write-Host "参考规则数量: $($referenceRules.Count)" -ForegroundColor Green

# 在写入文件前过滤规则
$filteredRules = $formattedRules | Where-Object {
    $rule = $_
    -not ($referenceRules.Contains($rule))
}

# 使用过滤后的规则创建输出内容
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime
# Generated AdBlock rules
# Total entries: $($filteredRules.Count)

$($filteredRules -join "`n")
"@

# 定义输出文件路径
$outputPath = "$PSScriptRoot/adblock_reject.list"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

# 输出生成的有效规则总数
Write-Host "生成的有效规则总数: $($filteredRules.Count)"
Add-Content -Path $logFilePath -Value "Total entries: $($filteredRules.Count)"
