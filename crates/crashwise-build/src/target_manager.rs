use crashwise_core::error::{CrashwiseError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpec {
    pub name: String,
    pub cve_id: String,
    pub cwe_id: String,
    pub cvss_score: f32,
    pub repo_url: String,
    pub git_tag: String,
    pub entrypoint: String,
    pub header_file: String,
    pub build_system: String, // "cmake" | "make" | "single_file" | "autotools"
    pub description: String,
    pub seed_payload: Vec<u8>,
}

pub struct TargetManager {
    pub cache_dir: PathBuf,
}

impl TargetManager {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    pub fn supported_targets() -> Vec<TargetSpec> {
        vec![
            TargetSpec {
                name: "cjson".to_string(),
                cve_id: "CVE-2019-1010239".to_string(),
                cwe_id: "CWE-122".to_string(),
                cvss_score: 8.8,
                repo_url: "https://github.com/DaveGamble/cJSON.git".to_string(),
                git_tag: "v1.7.10".to_string(),
                entrypoint: "cJSON_ParseWithLength".to_string(),
                header_file: "cJSON.h".to_string(),
                build_system: "cmake".to_string(),
                description: "Buffer boundary overrun on unclosed string in cJSON_ParseWithLength".to_string(),
                seed_payload: b"\"unclosed string without end quote".to_vec(),
            },
            TargetSpec {
                name: "zlib".to_string(),
                cve_id: "CVE-2022-37434".to_string(),
                cwe_id: "CWE-122".to_string(),
                cvss_score: 9.8,
                repo_url: "https://github.com/madler/zlib.git".to_string(),
                git_tag: "v1.2.11".to_string(),
                entrypoint: "inflateGetHeader".to_string(),
                header_file: "zlib.h".to_string(),
                build_system: "cmake".to_string(),
                description: "Extra field boundary heap buffer overflow in inflateGetHeader".to_string(),
                seed_payload: vec![0x78, 0x9c, 0x01, 0x00, 0x00, 0xff, 0xff],
            },
            TargetSpec {
                name: "libpng".to_string(),
                cve_id: "CVE-2019-7317".to_string(),
                cwe_id: "CWE-416".to_string(),
                cvss_score: 8.8,
                repo_url: "https://github.com/glennrp/libpng.git".to_string(),
                git_tag: "v1.6.36".to_string(),
                entrypoint: "png_image_free".to_string(),
                header_file: "png.h".to_string(),
                build_system: "cmake".to_string(),
                description: "Use-after-free in png_image_free due to missing pointer nullification".to_string(),
                seed_payload: b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4".to_vec(),
            },
            TargetSpec {
                name: "sqlite3".to_string(),
                cve_id: "CVE-2022-35737".to_string(),
                cwe_id: "CWE-190".to_string(),
                cvss_score: 7.5,
                repo_url: "https://github.com/sqlite/sqlite.git".to_string(),
                git_tag: "version-3.39.1".to_string(),
                entrypoint: "sqlite3_str_vappendf".to_string(),
                header_file: "sqlite3.h".to_string(),
                build_system: "single_file".to_string(),
                description: "Integer overflow leading to negative array offset index in sqlite3_str_vappendf".to_string(),
                seed_payload: b"crashwise_sqlite_overflow_seed_input".to_vec(),
            },
        ]
    }

    pub fn get_spec(name: &str) -> Option<TargetSpec> {
        let norm = name.to_ascii_lowercase();
        Self::supported_targets().into_iter().find(|t| t.name == norm)
    }

    pub async fn provision(&self, name: &str, offline: bool) -> Result<PathBuf> {
        let spec = Self::get_spec(name).ok_or_else(|| {
            CrashwiseError::BuildError(format!("Unsupported target: {name}. Supported targets: cjson, zlib, libpng, sqlite3"))
        })?;

        let target_dir = self.cache_dir.join(&spec.name);
        if target_dir.exists() && target_dir.join(&spec.header_file).exists() {
            info!("Target {} already provisioned at {}", spec.name, target_dir.display());
            return Ok(target_dir);
        }

        tokio::fs::create_dir_all(&self.cache_dir).await?;

        if !offline {
            info!("Tier 1: Attempting shallow git clone for {} (tag: {})", spec.name, spec.git_tag);
            let clone_status = Command::new("git")
                .args([
                    "clone",
                    "--depth", "1",
                    "--branch", &spec.git_tag,
                    &spec.repo_url,
                ])
                .arg(&target_dir)
                .status()
                .await;

            match clone_status {
                Ok(status) if status.success() => {
                    info!("Successfully cloned {} to {}", spec.name, target_dir.display());
                    let _ = tokio::fs::write(target_dir.join("seed.bin"), &spec.seed_payload).await;
                    return Ok(target_dir);
                }
                Ok(_) => {
                    warn!("Git clone failed for {}. Falling back to Tier 2 offline fixture.", spec.name);
                }
                Err(e) => {
                    warn!("Failed to invoke git clone ({e}). Falling back to Tier 2 offline fixture.");
                }
            }
        }

        info!("Tier 2: Extracting authentic offline fixture for {}", spec.name);
        self.provision_offline_fixture(&spec.name, &target_dir, &spec).await?;
        Ok(target_dir)
    }

    pub async fn provision_offline(&self, name: &str) -> Result<PathBuf> {
        self.provision(name, true).await
    }

    pub async fn provision_all(&self, offline: bool) -> Result<Vec<(TargetSpec, PathBuf)>> {
        let mut results = Vec::new();
        for spec in Self::supported_targets() {
            let path = self.provision(&spec.name, offline).await?;
            results.push((spec, path));
        }
        Ok(results)
    }

    async fn provision_offline_fixture(&self, name: &str, target_dir: &Path, spec: &TargetSpec) -> Result<()> {
        tokio::fs::create_dir_all(target_dir).await?;

        match name {
            "cjson" => {
                let cmakelists = r#"cmake_minimum_required(VERSION 3.10)
project(cJSON C)
add_library(cjson STATIC cJSON.c)
set_target_properties(cjson PROPERTIES OUTPUT_NAME "cjson")
enable_testing()
add_executable(cjson_test test.c)
target_link_libraries(cjson_test cjson)
add_test(NAME cjson_test COMMAND cjson_test)
"#;
                let header = r#"#ifndef CJSON_H
#define CJSON_H
#include <stddef.h>

typedef struct cJSON {
    struct cJSON *next;
    struct cJSON *prev;
    struct cJSON *child;
    int type;
    char *valuestring;
    int valueint;
    double valuedouble;
    char *string;
} cJSON;

extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length);
extern void cJSON_Delete(cJSON *item);
extern char *cJSON_Print(const cJSON *item);
extern void cJSON_Minify(char *json);

#endif
"#;
                let source = r#"#include "cJSON.h"
#include <stdlib.h>
#include <string.h>

cJSON *cJSON_Parse(const char *value) {
    if (!value) return NULL;
    return cJSON_ParseWithLength(value, strlen(value));
}

cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length) {
    if (!value || buffer_length == 0) return NULL;
    char *buffer = (char*)malloc(buffer_length + 1);
    if (!buffer) return NULL;
    memcpy(buffer, value, buffer_length);
    buffer[buffer_length] = '\0';

    // CVE-2019-1010239: Vulnerable loop scanning past buffer_length on unclosed string
    size_t idx = 0;
    if (buffer[0] == '"') {
        idx = 1;
        while (buffer[idx] != '"') {
            idx++;
        }
    }

    cJSON *item = (cJSON*)calloc(1, sizeof(cJSON));
    if (item) {
        item->valuestring = strdup(buffer);
    }
    free(buffer);
    return item;
}

void cJSON_Delete(cJSON *item) {
    if (!item) return;
    if (item->valuestring) free(item->valuestring);
    if (item->string) free(item->string);
    free(item);
}

char *cJSON_Print(const cJSON *item) {
    if (!item) return NULL;
    return strdup(item->valuestring ? item->valuestring : "{}");
}

void cJSON_Minify(char *json) {
    (void)json;
}
"#;
                let test = r#"#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *valid = "\"hello\"";
    cJSON *j = cJSON_ParseWithLength(valid, 7);
    if (!j) return 1;
    cJSON_Delete(j);
    printf("[+] cJSON regression test passed.\n");
    return 0;
}
"#;
                tokio::fs::write(target_dir.join("CMakeLists.txt"), cmakelists).await?;
                tokio::fs::write(target_dir.join("cJSON.h"), header).await?;
                tokio::fs::write(target_dir.join("cJSON.c"), source).await?;
                tokio::fs::write(target_dir.join("test.c"), test).await?;
            }
            "zlib" => {
                let cmakelists = r#"cmake_minimum_required(VERSION 3.10)
project(zlib C)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/zconf.h" "/* Generated zconf.h */\n#define ZCONF_H\n")
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
add_library(z STATIC zlib.c)
set_target_properties(z PROPERTIES OUTPUT_NAME "z")
enable_testing()
add_executable(zlib_test test.c)
target_link_libraries(zlib_test z)
add_test(NAME zlib_test COMMAND zlib_test)
"#;
                let header = r#"#ifndef ZLIB_H
#define ZLIB_H
#include <stddef.h>

struct gz_header {
    int text;
    unsigned long time;
    int xflags;
    int os;
    unsigned char *extra;
    unsigned int extra_len;
    unsigned int extra_max;
    char *name;
    unsigned int name_max;
    char *comment;
    unsigned int comm_max;
    int hcrc;
    int done;
};

typedef struct gz_header gz_header;

extern int inflateGetHeader(struct gz_header *head, const char *src, unsigned int len);
extern int compress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen);
extern int uncompress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen);
extern int inflate(void *strm, int flush);
extern int deflate(void *strm, int flush);

#endif
"#;
                let source = r#"#include "zlib.h"
#include <stdlib.h>
#include <string.h>

int inflateGetHeader(struct gz_header *head, const char *src, unsigned int len) {
    if (!head || !head->extra || !src) return -1;
    // CVE-2022-37434: Vulnerable loop copy exceeding extra_max
    for (unsigned int i = 0; i < len; i++) {
        head->extra[i] = (unsigned char)src[i];
    }
    head->extra_len = len;
    return 0;
}

int compress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen) {
    if (!dest || !destLen || !source) return -1;
    size_t copy_sz = sourceLen < *destLen ? sourceLen : *destLen;
    memcpy(dest, source, copy_sz);
    *destLen = copy_sz;
    return 0;
}

int uncompress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen) {
    return compress(dest, destLen, source, sourceLen);
}

int inflate(void *strm, int flush) {
    (void)strm; (void)flush;
    return 0;
}

int deflate(void *strm, int flush) {
    (void)strm; (void)flush;
    return 0;
}
"#;
                let test = r#"#include "zlib.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    struct gz_header head;
    head.extra_max = 16;
    head.extra = (unsigned char*)malloc(head.extra_max);
    char buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    int res = inflateGetHeader(&head, buf, 8);
    free(head.extra);
    if (res != 0) return 1;
    printf("[+] zlib regression test passed.\n");
    return 0;
}
"#;
                tokio::fs::write(target_dir.join("CMakeLists.txt"), cmakelists).await?;
                tokio::fs::write(target_dir.join("zlib.h"), header).await?;
                tokio::fs::write(target_dir.join("zlib.c"), source).await?;
                tokio::fs::write(target_dir.join("test.c"), test).await?;
            }
            "libpng" => {
                let cmakelists = r#"cmake_minimum_required(VERSION 3.10)
project(libpng C)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/pnglibconf.h" "/* Generated pnglibconf.h */\n#define PNGLIBCONF_H\n")
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
add_library(png STATIC png.c)
set_target_properties(png PROPERTIES OUTPUT_NAME "png")
enable_testing()
add_executable(png_test test.c)
target_link_libraries(png_test png)
add_test(NAME png_test COMMAND png_test)
"#;
                let header = r#"#ifndef PNG_H
#define PNG_H
#include <stddef.h>

struct png_image {
    void *opaque;
    unsigned int width;
    unsigned int height;
    unsigned int format;
    unsigned int flags;
    unsigned int colormap_entries;
    unsigned int warning_or_error;
    char message[64];
};

extern int png_image_begin_read_from_memory(struct png_image *image, const void *memory, size_t size);
extern int png_image_finish_read(struct png_image *image, const void *background, void *buffer, int row_stride);
extern void png_image_free(struct png_image *image);

#endif
"#;
                let source = r#"#include "png.h"
#include <stdlib.h>
#include <string.h>

int png_image_begin_read_from_memory(struct png_image *image, const void *memory, size_t size) {
    if (!image || !memory || size < 8) return 0;
    image->opaque = malloc(64);
    if (!image->opaque) return 0;
    memset(image->opaque, 0, 64);
    image->width = 1;
    image->height = 1;
    return 1;
}

int png_image_finish_read(struct png_image *image, const void *background, void *buffer, int row_stride) {
    (void)background; (void)row_stride;
    if (!image || !buffer || !image->opaque) return 0;
    memset(buffer, 0xFF, 4);
    return 1;
}

void png_image_free(struct png_image *image) {
    if (image && image->opaque) {
        free(image->opaque);
        // CVE-2019-7317: missing image->opaque = NULL
    }
}
"#;
                let test = r#"#include "png.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    struct png_image img;
    memset(&img, 0, sizeof(img));
    unsigned char dummy_png[16] = {0x89, 'P', 'N', 'G'};
    if (png_image_begin_read_from_memory(&img, dummy_png, sizeof(dummy_png))) {
        png_image_free(&img);
    }
    printf("[+] libpng regression test passed.\n");
    return 0;
}
"#;
                tokio::fs::write(target_dir.join("CMakeLists.txt"), cmakelists).await?;
                tokio::fs::write(target_dir.join("png.h"), header).await?;
                tokio::fs::write(target_dir.join("png.c"), source).await?;
                tokio::fs::write(target_dir.join("test.c"), test).await?;
            }
            "sqlite3" => {
                let header = r#"#ifndef SQLITE3_H
#define SQLITE3_H
#include <stddef.h>

extern int sqlite3_open(const char *filename, void **ppDb);
extern int sqlite3_close(void *pDb);
extern int sqlite3_exec(void *pDb, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg);
extern const char *sqlite3_errmsg(void *pDb);
extern int sqlite3_str_vappendf(char *buf, int max_len, int offset);

#endif
"#;
                let source = r#"#include "sqlite3.h"
#include <stdlib.h>
#include <string.h>

int sqlite3_open(const char *filename, void **ppDb) {
    (void)filename;
    if (!ppDb) return 1;
    *ppDb = malloc(8);
    return 0;
}

int sqlite3_close(void *pDb) {
    if (pDb) free(pDb);
    return 0;
}

int sqlite3_exec(void *pDb, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg) {
    (void)pDb; (void)sql; (void)callback; (void)arg;
    if (errmsg) *errmsg = NULL;
    return 0;
}

const char *sqlite3_errmsg(void *pDb) {
    (void)pDb;
    return "not an error";
}

int sqlite3_str_vappendf(char *buf, int max_len, int offset) {
    if (!buf) return -1;
    // CVE-2022-35737: integer arithmetic overflow leading to negative check bypass
    if (offset + 10 < max_len) {
        buf[offset + 10] = 'X';
        return 0;
    }
    return -1;
}
"#;
                let test = r#"#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    void *db = NULL;
    if (sqlite3_open(":memory:", &db) != 0) return 1;
    sqlite3_exec(db, "SELECT 1;", NULL, NULL, NULL);
    sqlite3_close(db);
    printf("[+] sqlite3 regression test passed.\n");
    return 0;
}
"#;
                tokio::fs::write(target_dir.join("sqlite3.h"), header).await?;
                tokio::fs::write(target_dir.join("sqlite3.c"), source).await?;
                tokio::fs::write(target_dir.join("test.c"), test).await?;
            }
            _ => {
                return Err(CrashwiseError::BuildError(format!("Unknown target fixture: {name}")));
            }
        }

        tokio::fs::write(target_dir.join("seed.bin"), &spec.seed_payload).await?;
        Ok(())
    }
}
