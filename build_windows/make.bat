if not "%1"=="" (
    set OUT=%1
) else (
    set OUT=espio
)

cl /c /Ox /Os /GL /GF /GS- /W4 /EHsc ../src/espio.cpp
cl /c /Ox /Os /GL /GF /GS- /W4 /EHsc /I../src ../examples/espio_test.c
rc -r espio.rc

link /DLL /LTCG espio.obj espio.res /OUT:%OUT%.dll
link /LTCG espio_test.obj espio.res %OUT%.lib /subsystem:console /OUT:%OUT%.exe
