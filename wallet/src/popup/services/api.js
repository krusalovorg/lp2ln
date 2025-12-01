const API_BASE_URL = 'http://localhost:8081';

// Готовые JSON пакеты для разных действий
export const API_ACTIONS = {
    // Генерация ключей
    GENERATE_KEYS: {
        act: 'generate_keys',
        protocol: 'SIGNAL'
    },
    
    // Получение информации о ноде
    GET_NODE_INFO: {
        act: 'get_node_info',
        protocol: 'SIGNAL'
    },
    
    // Загрузка файла
    UPLOAD_FILE: (file, options = {}) => ({
        act: 'save_file',
        protocol: 'TURN',
        data: {
            filename: file.name,
            contents: file,
            public: options.public ?? true,
            encrypted: options.encrypted ?? false,
            compressed: options.compressed ?? false,
            auto_decompress: options.auto_decompress ?? false
        }
    }),
    
    // Получение файла
    GET_FILE: (fileHash) => ({
        act: 'get_file',
        protocol: 'TURN',
        data: {
            file_hash: fileHash
        }
    }),
    
    // Обновление файла
    UPDATE_FILE: (fileHash, file, options = {}) => ({
        act: 'update_file',
        protocol: 'TURN',
        data: {
            file_hash: fileHash,
            filename: file.name,
            contents: file,
            public: options.public ?? true,
            encrypted: options.encrypted ?? false,
            compressed: options.compressed ?? false,
            auto_decompress: options.auto_decompress ?? false
        }
    }),
    
    // Удаление файла
    DELETE_FILE: (fileHash) => ({
        act: 'delete_file',
        protocol: 'TURN',
        data: {
            file_hash: fileHash
        }
    }),
    
    // Изменение доступа к файлу
    CHANGE_FILE_ACCESS: (fileHash, isPublic) => ({
        act: 'change_file_access',
        protocol: 'TURN',
        data: {
            file_hash: fileHash,
            public: isPublic
        }
    }),
    
    // Вызов контракта
    CALL_CONTRACT: (contractHash, functionName, payload) => ({
        act: 'request_contract',
        protocol: 'SIGNAL',
        data: {
            contract_hash: contractHash,
            function_name: functionName,
            payload: payload
        }
    })
};

// Функция для отправки запросов к API
export const sendApiRequest = async (action) => {
    try {
        const response = await fetch(`${API_BASE_URL}/api/packet`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(action)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
};

// Функция для получения информации о ноде
export const getNodeInfo = async () => {
    try {
        const response = await fetch(`${API_BASE_URL}/api/info`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Failed to get node info:', error);
        throw error;
    }
};

// Функция для загрузки файла
export const uploadFile = async (file, options = {}) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('public', options.public ?? true);
    formData.append('encrypted', options.encrypted ?? false);
    formData.append('compressed', options.compressed ?? false);
    formData.append('auto_decompress', options.auto_decompress ?? false);

    try {
        const response = await fetch(`${API_BASE_URL}/api/upload`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('File upload failed:', error);
        throw error;
    }
};

// Функция для получения файла
export const getFile = async (fileHash) => {
    try {
        const response = await fetch(`${API_BASE_URL}/api/file/${fileHash}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.blob();
    } catch (error) {
        console.error('Failed to get file:', error);
        throw error;
    }
};

// Функция для обновления файла
export const updateFile = async (fileHash, file, options = {}) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('file_hash', fileHash);
    formData.append('public', options.public ?? true);
    formData.append('encrypted', options.encrypted ?? false);
    formData.append('compressed', options.compressed ?? false);
    formData.append('auto_decompress', options.auto_decompress ?? false);

    try {
        const response = await fetch(`${API_BASE_URL}/api/update`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('File update failed:', error);
        throw error;
    }
};

// Функция для удаления файла
export const deleteFile = async (fileHash) => {
    try {
        const response = await fetch(`${API_BASE_URL}/api/file/${fileHash}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('File deletion failed:', error);
        throw error;
    }
};

// Функция для изменения доступа к файлу
export const changeFileAccess = async (fileHash, isPublic) => {
    try {
        const response = await fetch(`${API_BASE_URL}/api/file/${fileHash}/access`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ public: isPublic })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Failed to change file access:', error);
        throw error;
    }
};

// Функция для вызова контракта
export const callContract = async (contractHash, functionName, payload) => {
    try {
        const response = await fetch(`${API_BASE_URL}/api/contract/call`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                contract_hash: contractHash,
                function_name: functionName,
                payload: payload
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('Contract call failed:', error);
        throw error;
    }
};

// Получение списка всех файлов
export const getAllFiles = async () => {
    try {
        const response = await fetch(`${API_BASE_URL}/api/files`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Failed to get files list:', error);
        throw error;
    }
}; 