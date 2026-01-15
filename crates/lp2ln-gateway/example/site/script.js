// --- DOM Elements ---
const nodeIdEl = document.getElementById('node-id');
const hostTypeEl = document.getElementById('host-type');
const nodeStatusEl = document.getElementById('node-status');
const connectionTypeEl = document.getElementById('connection-type');
const currentUrlEl = document.getElementById('current-url');

const uploadForm = document.getElementById('upload-form');
const fileInput = document.getElementById('file-input');
const termsCheckbox = document.getElementById('terms-checkbox');
const uploadButton = document.getElementById('upload-button');
const uploadButtonText = document.getElementById('upload-button-text');
const uploadSpinner = document.getElementById('upload-spinner');
const uploadStatusEl = document.getElementById('upload-status');

const galleryGridEl = document.getElementById('gallery-grid');
const galleryLoadingTextEl = document.getElementById('gallery-loading-text');
const refreshGalleryBtn = document.getElementById('refresh-gallery-btn');

// --- API Interaction Functions ---
const URL_BASE = `${window.location.protocol}//${window.location.hostname}:8081`;

async function fetchCurrentNodeInfo() {
    try {
        const response = await fetch(`${URL_BASE}/api/info`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        return {
            nodeId: data.node_id || 'N/A',
            hostType: data.host_type || 'N/A',
            status: data.status || 'N/A',
            connectionType: data.connection_type || 'N/A'
        };
    } catch (error) {
        console.error("Ошибка при получении информации об узле:", error);
        return { nodeId: 'Ошибка', hostType: 'N/A', status: 'OFFLINE', connectionType: 'N/A' };
    }
}

async function handleUploadFile(file) {
    console.log("[Frontend] Starting file upload:", {
        name: file.name,
        size: file.size,
        type: file.type
    });

    const formData = new FormData();
    formData.append('file', file);
    formData.append('public', 'true');
    formData.append('encrypted', 'false');
    formData.append('compressed', 'false');
    formData.append('auto_decompress', 'false');
    formData.append('token', '');

    uploadButton.disabled = true;
    uploadButtonText.textContent = 'Загрузка...';
    uploadSpinner.classList.remove('hidden');
    uploadStatusEl.textContent = '';

    try {
        console.log("[Frontend] Sending file to server...");
        const response = await fetch(`${URL_BASE}/api/upload`, {
            method: 'POST',
            body: formData
        });
        
        console.log("[Frontend] Server response status:", response.status);
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: "Ошибка сервера" }));
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }
        const result = await response.json();
        console.log("[Frontend] Upload successful:", result);
        return result;
    } catch (error) {
        console.error("[Frontend] Upload error:", error);
        throw error;
    } finally {
        uploadButton.disabled = !termsCheckbox.checked;
        uploadButtonText.textContent = 'Загрузить в сеть';
        uploadSpinner.classList.add('hidden');
    }
}

async function fetchUploadedFiles() {
    if (galleryLoadingTextEl) galleryLoadingTextEl.textContent = 'Обновление галереи...';
    if (galleryGridEl) galleryGridEl.innerHTML = '';

    try {
        const response = await fetch(`${URL_BASE}/api/files`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error("Ошибка при получении списка файлов:", error);
        if (galleryLoadingTextEl) galleryLoadingTextEl.textContent = 'Ошибка загрузки галереи.';
        return [];
    }
}

function getDirectFileUrl(fileHash) {
    return `${window.location.protocol}//${window.location.hostname}:80/${fileHash}`;
}

// --- UI Update Functions ---
function updateNodeInfoUI(data) {
    if (nodeIdEl) nodeIdEl.textContent = data.nodeId || 'N/A';
    if (hostTypeEl) hostTypeEl.textContent = data.hostType || 'N/A';
    if (nodeStatusEl) {
         nodeStatusEl.textContent = data.status || 'N/A';
         if (data.status === 'ONLINE') {
            nodeStatusEl.className = 'text-lg neon-accent-green';
        } else if (data.status === 'OFFLINE') {
            nodeStatusEl.className = 'text-lg text-red-500';
        } else {
            nodeStatusEl.className = 'text-lg text-yellow-400';
        }
    }
    if (connectionTypeEl) connectionTypeEl.textContent = data.connectionType || 'N/A';
}

function displayGallery(files) {
    if (!galleryGridEl) return;
    galleryGridEl.innerHTML = '';
    
    if (!files || files.length === 0) {
        if (galleryLoadingTextEl) {
             galleryLoadingTextEl.textContent = 'В галерее пока нет файлов. Загрузите первый!';
             galleryLoadingTextEl.classList.remove('hidden');
             galleryGridEl.appendChild(galleryLoadingTextEl);
        }
        return;
    }
    if (galleryLoadingTextEl) galleryLoadingTextEl.classList.add('hidden');

    const imageMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
    
    files.forEach((file, index) => {
        const item = document.createElement('div');
        item.className = `gallery-item p-0 flex flex-col justify-between animate-fade-in delay-${(index % 5) * 100}`;

        const isImage = file.mime && imageMimeTypes.includes(file.mime.toLowerCase());
        let mediaElement;

        if (isImage) {
            const imgLink = document.createElement('a');
            imgLink.href = getDirectFileUrl(file.file_hash);
            imgLink.target = "_blank";
            const img = document.createElement('img');
            img.src = getDirectFileUrl(file.file_hash);
            img.alt = file.filename || 'Файл сети';
            img.onerror = () => { 
                img.src = `https://placehold.co/600x400/1A202C/E0E0E0?text=Error`; 
                img.alt = 'Ошибка загрузки';
            };
            img.className = 'w-full h-48 object-cover';
            imgLink.appendChild(img);
            mediaElement = imgLink;
        } else {
            mediaElement = document.createElement('div');
            mediaElement.className = 'w-full h-48 bg-gray-700 flex items-center justify-center text-gray-400 text-center p-4';
            mediaElement.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1"><path stroke-linecap="round" stroke-linejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" /></svg><p class="text-xs break-all">${file.filename || 'Файл'}</p>`;
        }
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'p-4';

        const name = document.createElement('p');
        name.className = 'font-semibold text-sm text-gray-200 truncate mb-1';
        name.textContent = file.filename || 'Без имени';
        name.title = file.filename || 'Без имени';

        const hash = document.createElement('p');
        hash.className = 'text-xs text-gray-400 font-jetbrains-mono truncate mb-1';
        hash.textContent = `${file.file_hash.substring(0,12)}...`;
        hash.title = file.file_hash;

        const size = document.createElement('p');
        size.className = 'text-xs text-gray-500 mb-2';
        size.textContent = `Размер: ${(file.size / 1024).toFixed(2)} KB`;
        
        const publicStatus = document.createElement('p');
        publicStatus.className = `text-xs mb-3 ${file.public ? 'text-green-400' : 'text-yellow-400'}`;
        publicStatus.innerHTML = file.public ? '🔓 <span class="align-middle">Публичный</span>' : '🔒 <span class="align-middle">Приватный</span>';

        const nodeInfo = document.createElement('p');
        nodeInfo.className = 'text-xs text-gray-400 mb-3 flex items-center gap-1';
        const nodeHash = file.storage_peer_key || 'Неизвестно';
        const shortNodeHash = nodeHash !== 'Неизвестно' ? `${nodeHash.substring(0,12)}...` : nodeHash;
        nodeInfo.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" /></svg> <span class="font-jetbrains-mono" title="${nodeHash}">${shortNodeHash}</span>`;

        const copyLinkButton = document.createElement('button');
        copyLinkButton.textContent = '🔗 Копировать ссылку';
        copyLinkButton.className = 'w-full text-xs bg-purple-600 hover:bg-purple-700 text-white py-1.5 px-3 rounded-md transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-purple-400 focus:ring-opacity-50';
        copyLinkButton.addEventListener('click', async (e) => {
            e.preventDefault(); e.stopPropagation();
            const urlToCopy = getDirectFileUrl(file.file_hash);
            try {
                await navigator.clipboard.writeText(urlToCopy);
                const originalText = copyLinkButton.textContent;
                copyLinkButton.textContent = '✓ Скопировано!';
                copyLinkButton.classList.replace('bg-purple-600', 'bg-green-600');
                copyLinkButton.classList.replace('hover:bg-purple-700', 'hover:bg-green-700');
                setTimeout(() => {
                    copyLinkButton.textContent = originalText;
                    copyLinkButton.classList.replace('bg-green-600','bg-purple-600');
                    copyLinkButton.classList.replace('hover:bg-green-700', 'hover:bg-purple-700');
                }, 2000);
            } catch (err) {
                console.error('Не удалось скопировать ссылку: ', err);
                const textArea = document.createElement("textarea");
                textArea.value = urlToCopy;
                document.body.appendChild(textArea);
                textArea.focus(); textArea.select();
                try {
                    document.execCommand('copy');
                } catch (errFallback) {
                    console.error('Fallback: не удалось скопировать', errFallback);
                    copyLinkButton.textContent = '❌ Ошибка';
                    setTimeout(() => { copyLinkButton.textContent = '🔗 Копировать ссылку'; }, 2000);
                }
                document.body.removeChild(textArea);
            }
        });

        item.appendChild(mediaElement);
        contentDiv.appendChild(name);
        contentDiv.appendChild(hash);
        contentDiv.appendChild(size);
        contentDiv.appendChild(publicStatus);
        contentDiv.appendChild(nodeInfo);
        contentDiv.appendChild(copyLinkButton);
        item.appendChild(contentDiv);
        galleryGridEl.appendChild(item);
    });
}

// --- Event Listeners ---
if (uploadForm) {
    uploadForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!termsCheckbox.checked) {
            uploadStatusEl.innerHTML = `<p class="text-yellow-400">Пожалуйста, примите Пользовательское соглашение перед загрузкой.</p>`;
            return;
        }
        const file = fileInput.files[0];
        if (!file) {
            uploadStatusEl.innerHTML = `<p class="text-red-400">Пожалуйста, выберите файл для загрузки.</p>`;
            return;
        }
        const maxSize = 10 * 1024 * 1024; // 10 MB
        if (file.size > maxSize) {
            uploadStatusEl.innerHTML = `<p class="text-red-400">Размер файла превышает 10 МБ. Пожалуйста, выберите файл меньшего размера.</p>`;
            return;
        }

        try {
            const result = await handleUploadFile(file);
            uploadStatusEl.innerHTML = `
                <div class="bg-green-500 bg-opacity-10 p-4 rounded-lg border border-green-500/30">
                    <p class="text-green-300 font-semibold turncate">Файл "${file.name}" успешно загружен!</p>
                    <p class="text-sm text-gray-300 mt-2 turncate">Hash: <span class="font-jetbrains-mono text-purple-300">${result.file_hash}</span></p>
                    <p class="text-sm text-gray-400 mt-1 turncate">Ссылка: <a href="${getDirectFileUrl(result.file_hash)}" target="_blank" class="text-purple-400 hover:underline">${getDirectFileUrl(result.file_hash)}</a></p>
                </div>`;
            uploadForm.reset();
            termsCheckbox.checked = false;
            uploadButton.disabled = true;
            await loadGallery();
        } catch (error) {
            uploadStatusEl.innerHTML = `
                <div class="bg-red-500 bg-opacity-10 p-4 rounded-lg border border-red-500/30">
                    <p class="text-red-300 font-semibold">Ошибка загрузки: ${error.message || 'Неизвестная ошибка'}</p>
                </div>`;
        }
    });
}

if (termsCheckbox) {
    termsCheckbox.addEventListener('change', () => {
        uploadButton.disabled = !termsCheckbox.checked;
    });
}

if (refreshGalleryBtn) {
    refreshGalleryBtn.addEventListener('click', loadGallery);
}

async function loadGallery() {
    if (galleryLoadingTextEl) {
        galleryLoadingTextEl.classList.remove('hidden');
        galleryLoadingTextEl.textContent = 'Обновление галереи...';
    }
     if (galleryGridEl && galleryLoadingTextEl && !galleryGridEl.contains(galleryLoadingTextEl)) {
        galleryGridEl.innerHTML = '';
        galleryGridEl.appendChild(galleryLoadingTextEl);
    }
    const files = await fetchUploadedFiles();
    displayGallery(files);
}

function setupSectionNavigation() {
    const sections = document.querySelectorAll('.section');
    const dots = document.querySelectorAll('.nav-dot');
    
    if (sections.length === 0 || dots.length === 0) {
        console.warn('Навигационные элементы или секции не найдены');
        return;
    }

    function updateActiveDotAndSection(activeIndex) {
        dots.forEach((dot, index) => {
            dot.classList.toggle('active', index === activeIndex);
        });
    }

    dots.forEach((dot, index) => {
        dot.addEventListener('click', () => {
            const targetSection = document.getElementById(dot.dataset.section);
            if (targetSection) {
                targetSection.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
    
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.4
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const intersectingSectionId = entry.target.id;
                dots.forEach((dot, index) => {
                    if (dot.dataset.section === intersectingSectionId) {
                        updateActiveDotAndSection(index);
                    }
                });
            }
        });
    }, observerOptions);

    sections.forEach(section => {
        observer.observe(section);
    });

    if (dots.length > 0) dots[0].classList.add('active');
}

async function showCurrentFileOwner() {
    const fileOwnerInfoEl = document.getElementById('file-owner-info');
    if (!fileOwnerInfoEl) return;
    const pathParts = window.location.pathname.split('/');
    const fileHash = pathParts[pathParts.length - 1].match(/^[a-fA-F0-9]{16,}$/) ? pathParts[pathParts.length - 1] : null;
    if (!fileHash) {
        fileOwnerInfoEl.textContent = 'Текущий файл не определён (хэш не найден в URL).';
        return;
    }
    fileOwnerInfoEl.textContent = 'Поиск владельца файла...';
    try {
        const files = await fetchUploadedFiles();
        const file = files.find(f => f.file_hash === fileHash);
        if (file) {
            fileOwnerInfoEl.innerHTML = `Текущий файл: <span class="font-jetbrains-mono text-purple-300">${fileHash}</span><br>Владелец (нода): <span class="font-jetbrains-mono text-green-300">${file.storage_peer_key || 'Неизвестно'}</span>`;
        } else {
            fileOwnerInfoEl.textContent = 'Файл с таким хэшем не найден в сети.';
        }
    } catch (e) {
        fileOwnerInfoEl.textContent = 'Ошибка при поиске владельца файла.';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    fetchCurrentNodeInfo().then(updateNodeInfoUI).catch(error => {
        console.error("Не удалось загрузить информацию об узле:", error);
        updateNodeInfoUI({ nodeId: 'Ошибка', hostType: 'N/A', status: 'OFFLINE', connectionType: 'N/A' });
    });

    try {
        if(currentUrlEl) {
            const span = currentUrlEl.querySelector('span');
            if(span) span.textContent = window.location.href;
        }
    } catch (e) {
        console.error("Ошибка при установке URL:", e);
    }
    
    loadGallery();
    setupSectionNavigation();
    showCurrentFileOwner();
}); 

showCurrentFileOwner();
