(function () {
    let workspaceHierarchy = {};
    let breadcrumb = [{ name: 'Root', path: [] }];
    let itemToMove = null;

    function showNotification(msg, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = msg;
        document.body.appendChild(notification);
        setTimeout(() => {
            notification.classList.add('show');
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }, 10);
    }

    async function apiRequest(endpoint, options = {}) {
        const { method = 'GET', body = null } = options;
        const headers = { 'Content-Type': 'application/json' };
        const config = {
            method,
            headers,
            credentials: 'include'
        };
        if (body) config.body = JSON.stringify(body);

        const response = await fetch(endpoint, config);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || `Failed to ${method} ${endpoint}`);
        }
        return response.json();
    }

    function renderBreadcrumb() {
        const breadcrumbEl = document.getElementById('breadcrumb');
        breadcrumbEl.innerHTML = breadcrumb.map((part, index) => {
            if (index === breadcrumb.length - 1) return `<span>/ ${part.name}</span>`;
            return `<a href="#" data-path="${part.path.join('/')}">/ ${part.name}</a>`;
        }).join(' ');

        breadcrumbEl.querySelectorAll('a').forEach(a => {
            a.onclick = (e) => {
                e.preventDefault();
                const name = e.target.textContent.substring(2);
                const index = breadcrumb.findIndex(b => b.name === name);
                breadcrumb = breadcrumb.slice(0, index + 1);
                renderFiles();
            };
        });
    }

    function createFileCard(item) {
        const card = document.createElement('div');
        card.className = 'file-card';
        const isFolder = item.type === 'folder';

        card.innerHTML = `
            <div class="file-icon ${isFolder ? 'folder-icon' : ''}" ${isFolder ? `data-path="${item.path}" data-name="${item.name}"` : ''}>
                <i class="fas fa-${isFolder ? 'folder' : 'file-alt'}"></i>
            </div>
            <div class="file-name">${item.name}</div>
            <div class="file-actions">
                <button class="btn btn-move">Move</button>
                <button class="btn btn-delete">Delete</button>
            </div>
        `;

        if (isFolder) {
            card.querySelector('.file-icon').onclick = (e) => {
                const { path, name } = e.currentTarget.dataset;
                breadcrumb.push({ name, path: path.split(',') });
                renderFiles();
            };
        }

        card.querySelector('.btn-move').onclick = () => openMoveModal(item);
        card.querySelector('.btn-delete').onclick = () => deleteFile(item);
        return card;
    }

    function renderFiles() {
        const container = document.getElementById('filesContainer');
        container.innerHTML = '';
        renderBreadcrumb();

        let currentNode = workspaceHierarchy;
        const currentPath = breadcrumb.length > 1 ? breadcrumb[breadcrumb.length - 1].path : [];

        for (const part of currentPath) {
            if (!part) continue;
            const folder = currentNode.children?.find(c => c.name === part && c.type === 'folder');
            if (!folder) {
                container.innerHTML = '<p>Folder not found.</p>';
                return;
            }
            currentNode = folder;
        }

        const items = currentNode.children || [];
        if (!items.length) {
            container.innerHTML = '<p>This folder is empty.</p>';
        }

        items.sort((a, b) => {
            if (a.type === 'folder' && b.type !== 'folder') return -1;
            if (a.type !== 'folder' && b.type === 'folder') return 1;
            return a.name.localeCompare(b.name);
        });

        items.forEach(item => container.appendChild(createFileCard(item)));
    }

    function getFolders(node, currentPath = [], allFolders = []) {
        if (node.type === 'folder') {
            if (node.name !== 'Root') {
                allFolders.push({
                    id: node.path || currentPath.join('/'),
                    name: currentPath.length > 0 ? `${currentPath.join(' / ')} / ${node.name}` : node.name
                });
            }
            if (node.children) {
                node.children.forEach(child => {
                    const newPath = [...currentPath];
                    if (node.name !== 'Root') {
                        newPath.push(node.name);
                    }
                    getFolders(child, newPath, allFolders);
                });
            }
        }
        return allFolders;
    }

    function openMoveModal(item) {
        itemToMove = item;
        document.getElementById('moveModalTitle').textContent = `Move "${item.name}"`;
        const modal = document.getElementById('moveModal');
        modal.style.display = 'flex';

        const allFolders = getFolders(workspaceHierarchy);
        
        const select = document.getElementById('folderSelect');
        select.innerHTML = '<option value="null">Root</option>';
        allFolders.forEach(folder => {
            if (folder.id !== item.id) {
                const option = document.createElement('option');
                option.value = folder.id; // The 'id' property now correctly holds the folder path
                option.textContent = folder.name;
                select.appendChild(option);
            }
        });
    }

    function closeMoveModal() {
        document.getElementById('moveModal').style.display = 'none';
    }

    async function confirmMove() {
        const newParentId = document.getElementById('folderSelect').value;
        if (itemToMove) {
            try {
                const payload = {
                    fileId: itemToMove.id,
                    parentId: newParentId === 'null' ? null : newParentId
                };
                console.log('Moving file with payload:', payload);
                await apiRequest('/api/files/move', {
                    method: 'PATCH',
                    body: payload
                });
                showNotification('Moved successfully', 'success');
                await refreshAll();
            } catch (e) {
                showNotification(e.message, 'error');
            } finally {
                closeMoveModal();
            }
        }
    }

    async function deleteFile(item) {
        if (!confirm(`Are you sure you want to delete "${item.name}"?`)) return;
        try {
            await apiRequest(`/api/sigma/files/${encodeURIComponent(item.id)}`, { method: 'DELETE' });
            showNotification('Deleted successfully', 'success');
            await refreshAll();
        } catch (e) {
            showNotification(e.message, 'error');
        }
    }

    async function createFolder() {
        const folderName = prompt("Enter new folder name:");
        if (!folderName) return;
        try {
            // This is a placeholder for the actual API call
            await apiRequest('/api/sigma/folders', {
                method: 'POST',
                body: { name: folderName, parentId: null } // Adjust parentId as needed
            });
            showNotification('Folder created successfully', 'success');
            await refreshAll();
        } catch (e) {
            showNotification(e.message, 'error');
        }
    }

    async function uploadFile() {
        // This is a placeholder for file upload logic
        alert("File upload functionality is not yet implemented.");
    }

    async function refreshAll() {
        try {
            const email = localStorage.getItem('userEmail');
            if (!email) {
                window.location.href = '/login';
                return;
            }
            workspaceHierarchy = await apiRequest(`/api/workspace?email=${encodeURIComponent(email)}`);
            renderFiles();
        } catch (e) {
            document.getElementById('filesContainer').innerHTML = `<p style="color:#ff8080">Error: ${e.message}</p>`;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        refreshAll();
        document.getElementById('confirmMoveBtn').onclick = confirmMove;
        window.filesApi = { closeMoveModal, createFolder, uploadFile };
    });
})();