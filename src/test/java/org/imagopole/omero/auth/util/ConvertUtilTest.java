package org.imagopole.omero.auth.util;

import static org.testng.Assert.assertEquals;
import static org.unitils.reflectionassert.ReflectionAssert.assertReflectionEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import ome.model.internal.Permissions;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.unitils.UnitilsTestNG;

public class ConvertUtilTest extends UnitilsTestNG {

    @Test(dataProvider = "tokenizeCsvDataProvider")
    public void tokenizeCsvTests(String input, List<String> expected) {
        List<String> result = ConvertUtil.tokenizeCsv(input);

        assertReflectionEquals(expected, result);
    }

    @Test(dataProvider = "toPermissionsOrNullDataProvider")
    public void toPermissionsOrNullTests(String input, Permissions expected) {
        Permissions result = ConvertUtil.toPermissionsOrNull(input);

        assertEquals(result, expected);
    }

    @DataProvider(name="tokenizeCsvDataProvider")
    private Object[][] provideCsv() {
        return new Object[][] {
            { null,            Collections.emptyList()                        },
            { "",              Collections.emptyList()                        },
            { "    ",          Collections.emptyList()                        },
            { "Str",           Arrays.asList(new String[] { "Str" })          },
            { "Str;Str",       Arrays.asList(new String[] { "Str;Str" })      },
            { "Str1,",         Arrays.asList(new String[] { "Str1" })         },
            { "Str1,Str2",     Arrays.asList(new String[] { "Str1", "Str2" }) },
            { " Str1 , Str2 ", Arrays.asList(new String[] { "Str1", "Str2" }) },
            { " ,Str2",        Arrays.asList(new String[] { "Str2" })         },
            { " , ",           Collections.emptyList()                        }
        };
    }

    @DataProvider(name="toPermissionsOrNullDataProvider")
    private Object[][] providePermissions() {
        return new Object[][] {
            { null,            null                                 },
            { "",              null                                 },
            { "    ",          null                                 },
            { "invalid",       Permissions.USER_PRIVATE             },
            { "private",       Permissions.USER_PRIVATE             },
            { "read-only",     Permissions.GROUP_READABLE           },
            { "read-annotate", ConvertUtil.PERMISSION_READ_ANNOTATE },
            { " private ",     Permissions.USER_PRIVATE             }
        };
    }

}
