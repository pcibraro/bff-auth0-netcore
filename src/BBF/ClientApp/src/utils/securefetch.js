export const securefetch = (url, options) => {
    const token = document.cookie.replace(/(?:(?:^|.*;\s*)X-CSRF-Token\s*\=\s*([^;]*).*$)|^.*$/, "$1");

    console.log(token);

    const headers = { "X-CSRF-Token": token };

    options = options || {};

    options.headers = { ...options.headers, ...headers };
        
    return fetch(url, options);
};

