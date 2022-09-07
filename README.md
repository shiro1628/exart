0. ntfs filesystem 전용 도구

1. 관리자 권한으로 실행

2. 필수 폴더(자동 초기화됨)  
   a. artifacts  
   b. artifacts\hash  
   c. artifacts\iconcache  
   d. artifacts\webcache  
   e. artifacts\collect_executed_files  
   f. artifacts\jumplist  
   g. artifacts\scriptfiles  
   h. artifacts\copy_from_mft\access, create, modify  
   i. artifacts\all_exe_dll  
   j. artifacts\all_log_extension_files  
   k. artifacts\recentfilesview  
   l. artifacts\collect_recentfilesview  
   m. artifacts\injected_codes  
   n. artifacts\shellbags  
   o. artifacts\special_eventlog  

3. "%TEMP%" 해쉬 수집 시 docker와 충돌 발생 docker를 종료해야함
