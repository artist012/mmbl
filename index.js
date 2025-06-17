
let ws = null;
let battleData = {};
let startTime = 0;
let lastUpdateTime = 0;
let totalBattleDamage = 0;
let expandedPlayers = new Set(); // Track which players have expanded skill breakdowns
let targetData = {}; // Track damage by target
let selectedTarget = null; // Currently selected target filter
let allTargets = new Set(); // All targets encountered in current battle
let battleHistory = []; // Store completed battles

// Initialize view mode
window.currentViewMode = 'live';
window.currentLiveData = null;

// Translation function for skill names
function translateSkillName(skillName) {
    // Check if translation data is available and if the skill name exists in the translation
    if (typeof DATA !== 'undefined' && DATA[skillName]) {
        return DATA[skillName];
    }
    // Return original skill name if no translation found
    return skillName;
}

// Class detection mapping
const classMapping = {
    'SwordMaster': { name: '검술사', color: 'linear-gradient(90deg, #8B4513, #A0522D)' },
    'Arbalist': { name: '석궁사수', color: 'linear-gradient(90deg, #228B22, #32CD32)' },
    'FireMage': { name: '화염술사', color: 'linear-gradient(90deg, #FF4500, #FF6347)' },
    'IceMage': { name: '얼탱', color: 'linear-gradient(90deg, #4169E1, #87CEEB)' },
    'Fighter': { name: '격투가', color: 'linear-gradient(90deg, #DC143C, #B22222)' },
    'LongBowMan': { name: '장궁병', color: 'linear-gradient(90deg, #2E8B57, #3CB371)' },
    'Healer': { name: '힐러', color: 'linear-gradient(90deg, #FFD700, #FFA500)' },
    'ExpertWarrior': { name: '전사', color: 'linear-gradient(90deg, #696969, #808080)' },
    'GreatSwordWarrior': { name: '대검전사', color: 'linear-gradient(90deg, #4B0082, #6A5ACD)' },
    'HighThief': { name: '도적', color: 'linear-gradient(90deg, #2F4F4F, #708090)' },
    'DualBlades': { name: '-듀-', color: 'linear-gradient(90deg, #8B008B, #DA70D6)' },
    'HighArcher': { name: '궁수', color: 'linear-gradient(90deg, #006400, #228B22)' },
    'HighMage': { name: '마법사', color: 'linear-gradient(90deg, #4B0082, #9400D3)' },
    'Priest': { name: '사제', color: 'linear-gradient(90deg, #F0F8FF, #E6E6FA)' },
    'Bard': { name: '음유시인', color: 'linear-gradient(90deg, #FF69B4, #FFB6C1)' },
    'Monk': { name: '수도사', color: 'linear-gradient(90deg, #CD853F, #D2691E)' },
    'Dancer': { name: '댄서', color: 'linear-gradient(90deg, #FF1493, #FF69B4)' },
    'BattleMusician': { name: '악사', color: 'linear-gradient(90deg, #9932CC, #BA55D3)' },

    "LightningMage": { name: '정전기술사', color: 'linear-gradient(90deg, #00CED1, #20B2AA)' }, // 조상님의 예지!
};

function detectPlayerClass(userData) {
    if (!userData.skills) return null;

    for (const skillName of Object.keys(userData.skills)) {
        for (const [classCode, classInfo] of Object.entries(classMapping)) {
            if (skillName.includes(classCode)) {
                return classCode;
            }
        }
    }
    return null;
}

// WebSocket connection
function connectWebSocket() {
    try {
        ws = new WebSocket("ws://localhost:8000");

        ws.onopen = function(evt) {
            console.log("웹소켓 연결됨");
            updateConnectionStatus(true);
        };

        ws.onclose = function(evt) {
            console.log("웹소켓 연결 해제됨");
            updateConnectionStatus(false);
            // Try to reconnect after 3 seconds
            setTimeout(connectWebSocket, 3000);
        };

        ws.onmessage = function(evt) {
            processDamageData(evt.data);
        };

        ws.onerror = function(evt) {
            console.error("웹소켓 오류:", evt);
            updateConnectionStatus(false);
        };
    } catch (error) {
        console.error("웹소켓 연결 실패:", error);
        updateConnectionStatus(false);
        setTimeout(connectWebSocket, 3000);
    }
}

function updateConnectionStatus(connected) {
    const statusElement = document.getElementById('connection-status');
    if (connected) {
        statusElement.textContent = '연결됨';
        statusElement.className = 'connection-status connected';
    } else {
        statusElement.textContent = '연결 끊김';
        statusElement.className = 'connection-status disconnected';
    }
}

function processDamageData(data) {
    // Don't process live data when viewing historical data
    if (window.currentViewMode === 'historical') {
        return;
    }
    
    const parts = data.split('|');
    if (parts.length !== 7) return;

    const timestamp = parseInt(parts[0]);
    const userId = parts[1];
    const target = parts[2];
    const skill = parts[3];
    const damage = parseInt(parts[4]);
    const critFlag = parseInt(parts[5]);
    const addHitFlag = parseInt(parts[6]);

    // Check for new battle (10+ second gap)
    if (lastUpdateTime === 0 || timestamp - lastUpdateTime > 10000) {
        startNewBattle(timestamp);
    }

    lastUpdateTime = timestamp;

    // Track targets
    allTargets.add(target);

    // Initialize target data if needed
    if (!targetData[target]) {
        targetData[target] = {
            totalDamage: 0,
            players: {}
        };
    }

    // Initialize user data if needed
    if (!battleData[userId]) {
        battleData[userId] = {
            totalDamage: 0,
            hitCount: 0,
            critCount: 0,
            addHitCount: 0,
            skills: {},
            targets: {} // Track damage by target for each user
        };
    }

    // Initialize target-specific user data
    if (!battleData[userId].targets[target]) {
        battleData[userId].targets[target] = {
            totalDamage: 0,
            hitCount: 0,
            critCount: 0,
            addHitCount: 0,
            skills: {}
        };
    }

    // Initialize skill data if needed
    if (!battleData[userId].skills[skill]) {
        battleData[userId].skills[skill] = {
            damage: 0,
            hits: 0,
            crits: 0,
            addHits: 0,
            targets: {} // Track damage by target for each skill
        };
    }

    // Initialize target-specific skill data
    if (!battleData[userId].targets[target].skills[skill]) {
        battleData[userId].targets[target].skills[skill] = {
            damage: 0,
            hits: 0,
            crits: 0,
            addHits: 0
        };
    }

    if (!battleData[userId].skills[skill].targets[target]) {
        battleData[userId].skills[skill].targets[target] = {
            damage: 0,
            hits: 0,
            crits: 0,
            addHits: 0
        };
    }

    // Update overall data
    battleData[userId].totalDamage += damage;
    battleData[userId].skills[skill].damage += damage;
    targetData[target].totalDamage += damage;

    // Update target-specific data
    battleData[userId].targets[target].totalDamage += damage;
    battleData[userId].targets[target].skills[skill].damage += damage;
    battleData[userId].skills[skill].targets[target].damage += damage;

    // Only count as a hit if it's not an additional hit
    if (!addHitFlag) {
        battleData[userId].hitCount += 1;
        battleData[userId].skills[skill].hits += 1;
        battleData[userId].targets[target].hitCount += 1;
        battleData[userId].targets[target].skills[skill].hits += 1;
        battleData[userId].skills[skill].targets[target].hits += 1;
    }

    if (critFlag) {
        battleData[userId].critCount += 1;
        battleData[userId].skills[skill].crits += 1;
        battleData[userId].targets[target].critCount += 1;
        battleData[userId].targets[target].skills[skill].crits += 1;
        battleData[userId].skills[skill].targets[target].crits += 1;
    }

    if (addHitFlag) {
        battleData[userId].addHitCount += 1;
        battleData[userId].skills[skill].addHits += 1;
        battleData[userId].targets[target].addHitCount += 1;
        battleData[userId].targets[target].skills[skill].addHits += 1;
        battleData[userId].skills[skill].targets[target].addHits += 1;
    }

    totalBattleDamage += damage;
}

function startNewBattle(timestamp) {
    console.log("새로운 전투 시작");
    
    // Don't start new battle when viewing historical data
    if (window.currentViewMode === 'historical') {
        return;
    }
    
    // Save previous battle to history if it had data
    if (Object.keys(battleData).length > 0 && totalBattleDamage > 0) {
        saveBattleToHistory();
    }
    
    battleData = {};
    targetData = {};
    allTargets.clear();
    selectedTarget = null;
    startTime = timestamp;
    totalBattleDamage = 0;
    expandedPlayers.clear(); // Clear expanded state for new battle
    updateDisplay();
}

function updateDisplay() {
    updateBattleInfo();
    updateTargetList();
    updatePlayerRankings();
    updateBattleHistory(); // Update battle history to show current battle
    updateEndBattleButton(); // Update end battle button visibility
}

function updateBattleInfo() {
    let battleTime = 0;
    
    // Use appropriate timing based on view mode
    if (window.currentViewMode === 'historical' && window.historicalBattleData) {
        battleTime = window.historicalBattleData.duration;
    } else {
        battleTime = lastUpdateTime > 0 ? Math.floor((lastUpdateTime - startTime) / 1000) : 0;
    }
    const playerCount = Object.keys(battleData).length;

    // Calculate RDPS based on selected target filter
    let raidDps = 0;
    let detectedPlayerCount = 0;
    let displayTotalDamage = totalBattleDamage;

    if (selectedTarget && targetData[selectedTarget]) {
        displayTotalDamage = targetData[selectedTarget].totalDamage;
    }

    if (battleTime > 0) {
        for (const [userId, userData] of Object.entries(battleData)) {
            const detectedClass = detectPlayerClass(userData);
            if (detectedClass && classMapping[detectedClass]) {
                let playerDamage = userData.totalDamage;
                
                // Use filtered damage if target is selected
                if (selectedTarget && userData.targets[selectedTarget]) {
                    playerDamage = userData.targets[selectedTarget].totalDamage;
                }
                
                if (playerDamage > 0) {
                    const playerDps = Math.floor(playerDamage / battleTime);
                    raidDps += playerDps;
                    detectedPlayerCount++;
                }
            }
        }
    }

    document.getElementById('battle-time').textContent = `${battleTime}초`;
    document.getElementById('total-damage').textContent = displayTotalDamage.toLocaleString();
    document.getElementById('raid-dps').textContent = raidDps.toLocaleString();
    document.getElementById('player-count').textContent = detectedPlayerCount;
}

function updateTargetList() {
    const container = document.getElementById('target-list');

    if (allTargets.size === 0) {
        container.innerHTML = '<div class="no-targets">타겟 데이터를 기다리는 중...</div>';
        return;
    }

    // Get list of identified player names (those with detected classes)
    const identifiedPlayers = new Set();
    for (const [userId, userData] of Object.entries(battleData)) {
        const detectedClass = detectPlayerClass(userData);
        if (detectedClass && classMapping[detectedClass]) {
            identifiedPlayers.add(userId);
        }
    }

    // Filter out targets that are identified as players and sort by total damage
    const sortedTargets = Array.from(allTargets)
        .filter(target => !identifiedPlayers.has(target)) // Remove identified players
        .map(target => ({
            name: target,
            damage: targetData[target]?.totalDamage || 0
        }))
        .sort((a, b) => b.damage - a.damage);

    if (sortedTargets.length === 0) {
        container.innerHTML = '<div class="no-targets">필터링할 타겟이 없습니다.</div>';
        return;
    }

    let html = '';
    sortedTargets.forEach(target => {
        const isSelected = selectedTarget === target.name;
        const targetDisplayName = target.name.substring(0, 16) || '알 수 없는 타겟';
        
        html += `
            <div class="target-item ${isSelected ? 'selected' : ''}" onclick="selectTarget('${target.name}')">
                <div class="target-name">${targetDisplayName}</div>
                <div class="target-damage">${target.damage.toLocaleString()}</div>
            </div>
        `;
    });

    container.innerHTML = html;
    
    // Check if scrolling is needed and add/remove scrollable class
    setTimeout(() => {
        const targetListElement = document.getElementById('target-list');
        
        // Check if content overflows the container
        if (targetListElement.scrollHeight > targetListElement.clientHeight) {
            targetListElement.classList.add('scrollable');
        } else {
            targetListElement.classList.remove('scrollable');
        }
    }, 0);
}

function updatePlayerRankings() {
    const container = document.getElementById('player-rankings');

    if (Object.keys(battleData).length === 0) {
        container.innerHTML = `
            <div class="ranking-header">
                <div>순위</div>
                <div>플레이어</div>
                <div>데미지 (DPS)</div>
            </div>
            <div class="no-data">데미지 데이터를 기다리는 중...</div>
        `;
        return;
    }

    // Get filtered data based on selected target
    const getFilteredData = (userData) => {
        if (!selectedTarget) {
            return userData;
        }
        return userData.targets[selectedTarget] || {
            totalDamage: 0,
            hitCount: 0,
            critCount: 0,
            addHitCount: 0,
            skills: {}
        };
    };

    // Sort players by filtered damage
    const sortedPlayers = Object.entries(battleData)
        .map(([userId, userData]) => [userId, getFilteredData(userData)])
        .filter(([, filteredData]) => filteredData.totalDamage > 0)
        .sort(([,a], [,b]) => b.totalDamage - a.totalDamage);

    const maxDamage = sortedPlayers.length > 0 ? sortedPlayers[0][1].totalDamage : 1;
    const battleTime = lastUpdateTime > 0 ? (lastUpdateTime - startTime) / 1000 : 1;
    
    // Calculate filtered total damage
    const filteredTotalDamage = selectedTarget
        ? (targetData[selectedTarget]?.totalDamage || 0)
        : totalBattleDamage;

    let html = `
        <div class="ranking-header">
            <div>순위</div>
            <div>플레이어</div>
            <div>데미지 (DPS)</div>
        </div>
    `;

    if (selectedTarget) {
        html += `
            <div class="filter-info">
                🎯 필터링된 타겟: ${selectedTarget.substring(0, 20)}
            </div>
        `;
    }

    let displayedPlayerIndex = 0;
    sortedPlayers.forEach(([userId, filteredData]) => {
        // Detect player class from original data
        const detectedClass = detectPlayerClass(battleData[userId]);

        // Only display players whose class has been detected
        if (!detectedClass || !classMapping[detectedClass]) {
            return; // Skip this player
        }

        const playerDps = Math.floor(filteredData.totalDamage / battleTime);
        const playerPercentage = filteredTotalDamage > 0
            ? ((filteredData.totalDamage / filteredTotalDamage) * 100).toFixed(1)
            : 0;
        const totalHits = filteredData.hitCount + filteredData.addHitCount;
        const critRate = totalHits > 0 ? ((filteredData.critCount / totalHits) * 100).toFixed(1) : 0;
        const barWidth = (filteredData.totalDamage / maxDamage) * 100;

        const barColor = classMapping[detectedClass].color;
        const className = classMapping[detectedClass].name;

        const rankClass = displayedPlayerIndex < 3 ? `rank-${displayedPlayerIndex + 1}` : '';
        const displayName = `${className} ${userId.substring(0, 8)}`;

        html += `
            <div class="player-bar" onclick="toggleSkillBreakdown('${userId}')">
                <div class="player-bar-fill" style="width: ${barWidth}%; background: ${barColor};"></div>
                <div class="player-bar-content">
                    <div class="rank-section">
                        <div class="rank-number ${rankClass}">${displayedPlayerIndex + 1}</div>
                    </div>
                    <div class="player-name">
                        ${displayName}
                    </div>
                    <div class="stat-value damage-value">${filteredData.totalDamage.toLocaleString()} (${playerDps.toLocaleString()})</div>
                </div>
            </div>
            <div class="skill-breakdown ${expandedPlayers.has(userId) ? 'show' : ''}" id="skills-${userId}">
                <div class="skill-breakdown-header">유저 ${userId.substring(0, 8)} - 스킬 상세</div>
                ${generateSkillBreakdown(userId, filteredData)}
            </div>
        `;

        displayedPlayerIndex++;
    });

    container.innerHTML = html;

    // Remove updating animation after a short delay
    setTimeout(() => {
        document.querySelectorAll('.updating').forEach(el => {
            el.classList.remove('updating');
        });
    }, 500);
}

function generateSkillBreakdown(userId, userData) {
    if (!userData.skills || Object.keys(userData.skills).length === 0) {
        return '<div style="color: #7f8c8d; text-align: center; padding: 20px;">스킬 데이터가 없습니다.</div>';
    }

    const sortedSkills = Object.entries(userData.skills)
        .sort(([,a], [,b]) => b.damage - a.damage);

    const maxSkillDamage = sortedSkills.length > 0 ? sortedSkills[0][1].damage : 1;
    
    // Use appropriate timing based on view mode
    let battleTime = 1;
    if (window.currentViewMode === 'historical' && window.historicalBattleData) {
        battleTime = window.historicalBattleData.duration;
    } else {
        battleTime = lastUpdateTime > 0 ? (lastUpdateTime - startTime) / 1000 : 1;
    }

    let skillHtml = '';
    sortedSkills.forEach(([skillName, skillData], skillIndex) => {
        const skillPercentage = ((skillData.damage / userData.totalDamage) * 100).toFixed(1);
        const skillDps = Math.floor(skillData.damage / battleTime);
        const skillTotalHits = skillData.hits + skillData.addHits;
        const skillCritRate = skillTotalHits > 0 ? ((skillData.crits / skillTotalHits) * 100).toFixed(1) : 0;
        const barWidth = (skillData.damage / maxSkillDamage) * 100;

        let skillBarClass = 'skill-item-fill';
        if (skillIndex === 0) skillBarClass += ' top-skill';
        else if (skillCritRate > 30) skillBarClass += ' crit-heavy';

        // Translate skill name if translation exists
        const translatedSkillName = translateSkillName(skillName);
        
        skillHtml += `
            <div class="skill-item">
                <div class="${skillBarClass}" style="width: ${barWidth}%">
                    <div class="skill-item-info">${translatedSkillName}</div>
                </div>
                <div class="skill-item-stats">
                    타수 ${skillData.hits} | 크리 ${skillCritRate}% | 추가타율 ${skillData.hits > 0 ? ((skillData.addHits / skillData.hits) * 100).toFixed(1) : 0}% | ${skillData.damage.toLocaleString()} (${skillPercentage}%)
                </div>
            </div>
        `;
    });

    return skillHtml;
}

function toggleSkillBreakdown(userId) {
    const skillBreakdown = document.getElementById(`skills-${userId}`);
    if (!skillBreakdown) return;

    if (expandedPlayers.has(userId)) {
        // Player is currently expanded, so collapse it
        expandedPlayers.delete(userId);
        skillBreakdown.classList.remove('show');
    } else {
        // Collapse all other breakdowns first
        document.querySelectorAll('.skill-breakdown.show').forEach(el => {
            el.classList.remove('show');
        });
        expandedPlayers.clear();

        // Expand this player's breakdown
        expandedPlayers.add(userId);

        // Update the breakdown content with latest data
        const userData = battleData[userId];
        if (userData) {
            // Get filtered data for skill breakdown
            const filteredData = selectedTarget && userData.targets[selectedTarget]
                ? userData.targets[selectedTarget]
                : userData;
            
            const targetInfo = selectedTarget ? ` (${selectedTarget.substring(0, 12)})` : '';
            
            skillBreakdown.innerHTML = `
                <div class="skill-breakdown-header">유저 ${userId.substring(0, 8)} - 스킬 상세${targetInfo}</div>
                ${generateSkillBreakdown(userId, filteredData)}
            `;
        }

        skillBreakdown.classList.add('show', 'animate');

        // Remove animate class after animation completes
        setTimeout(() => {
            skillBreakdown.classList.remove('animate');
        }, 300);
    }
}

function selectTarget(targetName) {
    selectedTarget = targetName;
    updateDisplay();
}

function clearTargetFilter() {
    selectedTarget = null;
    updateDisplay();
}

function saveBattleToHistory() {
    const battleTime = lastUpdateTime > 0 ? Math.floor((lastUpdateTime - startTime) / 1000) : 0;
    if (battleTime < 5) return; // Don't save very short battles
    
    // Calculate total RDPS
    let totalRaidDps = 0;
    let detectedPlayerCount = 0;
    
    if (battleTime > 0) {
        for (const [userId, userData] of Object.entries(battleData)) {
            const detectedClass = detectPlayerClass(userData);
            if (detectedClass && classMapping[detectedClass]) {
                const playerDps = Math.floor(userData.totalDamage / battleTime);
                totalRaidDps += playerDps;
                detectedPlayerCount++;
            }
        }
    }
    
    // Create battle summary
    const battleSummary = {
        id: Date.now(),
        timestamp: new Date().toLocaleString('ko-KR'),
        duration: battleTime,
        totalDamage: totalBattleDamage,
        raidDps: totalRaidDps,
        playerCount: detectedPlayerCount,
        players: JSON.parse(JSON.stringify(battleData)), // Deep copy
        targets: JSON.parse(JSON.stringify(targetData)),
        topPlayer: getTopPlayer()
    };
    
    battleHistory.unshift(battleSummary); // Add to beginning
    
    // Keep only last 20 battles
    if (battleHistory.length > 20) {
        battleHistory = battleHistory.slice(0, 20);
    }
    
    // Save to localStorage
    localStorage.setItem('mm_battle_history', JSON.stringify(battleHistory));
    
    // Update history display
    updateBattleHistory();
}

function getTopPlayer() {
    let topPlayer = null;
    let maxDamage = 0;
    
    for (const [userId, userData] of Object.entries(battleData)) {
        const detectedClass = detectPlayerClass(userData);
        if (detectedClass && classMapping[detectedClass] && userData.totalDamage > maxDamage) {
            maxDamage = userData.totalDamage;
            topPlayer = {
                id: userId,
                class: classMapping[detectedClass].name,
                damage: userData.totalDamage
            };
        }
    }
    
    return topPlayer;
}


function updateBattleHistory() {
    const container = document.getElementById('history-list');
    
    let html = '';
    
    // Add current battle navigation if there's ongoing battle data
    // Use live data if available, otherwise use current data only if in live mode
    let currentBattleData, currentTargetData, currentTotalDamage, currentStartTime, currentLastUpdateTime;
    
    if (window.currentLiveData) {
        // Use preserved live data when viewing historical battles
        currentBattleData = window.currentLiveData.battleData;
        currentTargetData = window.currentLiveData.targetData;
        currentTotalDamage = window.currentLiveData.totalBattleDamage;
        currentStartTime = window.currentLiveData.startTime;
        currentLastUpdateTime = window.currentLiveData.lastUpdateTime;
    } else if (window.currentViewMode === 'live') {
        // Use current data when in live mode
        currentBattleData = battleData;
        currentTargetData = targetData;
        currentTotalDamage = totalBattleDamage;
        currentStartTime = startTime;
        currentLastUpdateTime = lastUpdateTime;
    }
    
    if (currentBattleData && Object.keys(currentBattleData).length > 0 && currentTotalDamage > 0) {
        const currentBattleTime = currentLastUpdateTime > 0 ? Math.floor((currentLastUpdateTime - currentStartTime) / 1000) : 0;
        const currentRaidDps = calculateRaidDpsForData(currentBattleData, currentBattleTime);
        const currentPlayerCount = getPlayerCountForData(currentBattleData);
        
        html += `
            <div class="history-item current-battle" onclick="viewCurrentBattle()">
                <div class="current-battle-indicator">🔴 현재 진행중인 전투</div>
                <div class="history-header-row">
                    <div class="history-time">실시간</div>
                    <div class="history-duration">${currentBattleTime}초</div>
                </div>
                <div class="history-stats">
                    <div class="history-stat">
                        <span class="stat-label">총 데미지:</span>
                        <span class="stat-value">${currentTotalDamage.toLocaleString()}</span>
                    </div>
                    <div class="history-stat">
                        <span class="stat-label">총 DPS:</span>
                        <span class="stat-value">${currentRaidDps.toLocaleString()}</span>
                    </div>
                    <div class="history-stat">
                        <span class="stat-label">참여자:</span>
                        <span class="stat-value">${currentPlayerCount}명</span>
                    </div>
                </div>
            </div>
        `;
    }
    
    if (battleHistory.length === 0) {
        if (html === '') {
            container.innerHTML = '<div class="no-history">저장된 전투 기록이 없습니다.</div>';
            return;
        } else {
            container.innerHTML = html;
            return;
        }
    }
    
    battleHistory.forEach((battle, index) => {
        const avgDps = battle.playerCount > 0 ? Math.floor(battle.raidDps / battle.playerCount) : 0;
        
        html += `
            <div class="history-item" onclick="viewBattleDetails(${index})">
                <div class="history-header-row">
                    <div class="history-time">${battle.timestamp}</div>
                    <div class="history-duration">${battle.duration}초</div>
                </div>
                <div class="history-stats">
                    <div class="history-stat">
                        <span class="stat-label">총 데미지:</span>
                        <span class="stat-value">${battle.totalDamage.toLocaleString()}</span>
                    </div>
                    <div class="history-stat">
                        <span class="stat-label">RDPS:</span>
                        <span class="stat-value">${battle.raidDps.toLocaleString()}</span>
                    </div>
                    <div class="history-stat">
                        <span class="stat-label">참여자:</span>
                        <span class="stat-value">${battle.playerCount}명</span>
                    </div>
                </div>
                ${battle.topPlayer ? `
                    <div class="history-top-player">
                        🏆 ${battle.topPlayer.class} ${battle.topPlayer.id.substring(0, 8)} - ${battle.topPlayer.damage.toLocaleString()}
                    </div>
                ` : ''}
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function viewBattleDetails(index) {
    const battle = battleHistory[index];
    if (!battle) return;
    
    // Load historical battle data into main view
    loadHistoricalBattle(battle);
}

function loadHistoricalBattle(battle) {
    // Only store live data if we're not already in historical view
    if (window.currentViewMode === 'live') {
        // Store current live data with proper timing preservation
        const currentLiveData = {
            battleData: JSON.parse(JSON.stringify(battleData)),
            targetData: JSON.parse(JSON.stringify(targetData)),
            allTargets: new Set(allTargets),
            selectedTarget: selectedTarget,
            startTime: startTime,
            lastUpdateTime: lastUpdateTime,
            totalBattleDamage: totalBattleDamage,
            expandedPlayers: new Set(expandedPlayers),
            isHistorical: false
        };
        window.currentLiveData = currentLiveData;
    }
    // If already in historical view, keep the existing live data preserved
    
    // Store historical timing separately to avoid overwriting live timing
    const historicalStartTime = Date.now() - (battle.duration * 1000);
    const historicalLastUpdateTime = Date.now();
    
    // Load historical data
    battleData = JSON.parse(JSON.stringify(battle.players));
    targetData = JSON.parse(JSON.stringify(battle.targets));
    allTargets = new Set(Object.keys(battle.targets));
    selectedTarget = null;
    totalBattleDamage = battle.totalDamage;
    expandedPlayers.clear();
    
    // Mark as historical view
    window.currentViewMode = 'historical';
    window.historicalBattleData = {
        startTime: historicalStartTime,
        lastUpdateTime: historicalLastUpdateTime,
        duration: battle.duration
    };
    
    // Update displays
    updateDisplay();
    updateTargetList();
    
    // Show historical indicator
    showHistoricalIndicator(battle);
}

function showHistoricalIndicator(battle) {
    // Add historical indicator to the header
    const header = document.querySelector('.header');
    let indicator = document.getElementById('historical-indicator');
    
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'historical-indicator';
        indicator.className = 'historical-indicator';
        header.appendChild(indicator);
    }
    
    indicator.innerHTML = `
        <div class="historical-info">
            📜 과거 전투 기록 보기 - ${battle.timestamp}
            <button class="back-to-live-btn" onclick="backToLiveView()">실시간으로 돌아가기</button>
        </div>
    `;
    indicator.style.display = 'block';
}

function backToLiveView() {
    if (!window.currentLiveData) return;
    
    // Restore live data
    const liveData = window.currentLiveData;
    battleData = liveData.battleData;
    targetData = liveData.targetData;
    allTargets = liveData.allTargets;
    selectedTarget = liveData.selectedTarget;
    startTime = liveData.startTime;
    lastUpdateTime = liveData.lastUpdateTime;
    totalBattleDamage = liveData.totalBattleDamage;
    expandedPlayers = liveData.expandedPlayers || new Set();
    
    // Clear historical mode
    window.currentViewMode = 'live';
    window.currentLiveData = null;
    window.historicalBattleData = null;
    
    // Hide historical indicator
    const indicator = document.getElementById('historical-indicator');
    if (indicator) {
        indicator.style.display = 'none';
    }
    
    // Update displays
    updateDisplay();
    updateTargetList();
}

function calculateCurrentRaidDps() {
    const battleTime = lastUpdateTime > 0 ? Math.floor((lastUpdateTime - startTime) / 1000) : 0;
    let raidDps = 0;
    
    if (battleTime > 0) {
        for (const [userId, userData] of Object.entries(battleData)) {
            const detectedClass = detectPlayerClass(userData);
            if (detectedClass && classMapping[detectedClass]) {
                const playerDps = Math.floor(userData.totalDamage / battleTime);
                raidDps += playerDps;
            }
        }
    }
    
    return raidDps;
}

function getCurrentPlayerCount() {
    let detectedPlayerCount = 0;
    
    for (const [userId, userData] of Object.entries(battleData)) {
        const detectedClass = detectPlayerClass(userData);
        if (detectedClass && classMapping[detectedClass]) {
            detectedPlayerCount++;
        }
    }
    
    return detectedPlayerCount;
}

function calculateRaidDpsForData(battleDataToUse, battleTimeToUse) {
    let raidDps = 0;
    
    if (battleTimeToUse > 0) {
        for (const [userId, userData] of Object.entries(battleDataToUse)) {
            const detectedClass = detectPlayerClass(userData);
            if (detectedClass && classMapping[detectedClass]) {
                const playerDps = Math.floor(userData.totalDamage / battleTimeToUse);
                raidDps += playerDps;
            }
        }
    }
    
    return raidDps;
}

function getPlayerCountForData(battleDataToUse) {
    let detectedPlayerCount = 0;
    
    for (const [userId, userData] of Object.entries(battleDataToUse)) {
        const detectedClass = detectPlayerClass(userData);
        if (detectedClass && classMapping[detectedClass]) {
            detectedPlayerCount++;
        }
    }
    
    return detectedPlayerCount;
}

function viewCurrentBattle() {
    // If in historical view, return to live view
    if (window.currentViewMode === 'historical') {
        backToLiveView();
    }
    
    // The current battle is now always visible in the main content area
    // No need to switch sidebars since both are always visible
}

function clearBattleHistory() {
    if (confirm('모든 전투 기록을 삭제하시겠습니까?')) {
        battleHistory = [];
        localStorage.removeItem('mm_battle_history');
        updateBattleHistory();
    }
}

function downloadBattleHistory() {
    const saved = localStorage.getItem('mm_battle_history');
    if (!saved) {
        alert('저장된 전투 기록이 없습니다.');
        return;
    }
    const blob = new Blob([saved], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const filename = 'battle_history_' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function loadBattleHistory() {
    const saved = localStorage.getItem('mm_battle_history');
    if (saved) {
        try {
            battleHistory = JSON.parse(saved);
        } catch (e) {
            console.error('Failed to load battle history:', e);
            battleHistory = [];
        }
    }
}

function updateEndBattleButton() {
    const endBattleBtn = document.getElementById('end-battle-btn');
    
    // Show button only if there's ongoing battle data and we're in live view
    if (window.currentViewMode === 'live' && Object.keys(battleData).length > 0 && totalBattleDamage > 0) {
        endBattleBtn.style.display = 'block';
    } else {
        endBattleBtn.style.display = 'none';
    }
}

function endCurrentBattle() {
    if (Object.keys(battleData).length === 0 || totalBattleDamage === 0) {
        alert('종료할 전투가 없습니다.');
        return;
    }
    
    if (confirm('현재 전투를 종료하고 기록에 저장하시겠습니까?')) {
        // Save current battle to history
        saveBattleToHistory();
        
        // Reset battle data
        battleData = {};
        targetData = {};
        allTargets.clear();
        selectedTarget = null;
        startTime = 0;
        lastUpdateTime = 0;
        totalBattleDamage = 0;
        expandedPlayers.clear();
        
        // Update displays
        updateDisplay();
        
        alert('전투가 종료되고 기록에 저장되었습니다.');
    }
}

// Initialize
loadBattleHistory();
updateBattleHistory(); // Initialize battle history display
connectWebSocket();

// Update display every second
setInterval(updateDisplay, 1000);
